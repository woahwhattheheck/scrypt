#!/usr/bin/env python3
"""Measure native scrypt PR 428 test sensitivity using isolated source mutants.

Only a disposable, built checkout and temporary test files are used. Mutated
sources never leave the temporary variant directories or enter a source branch.
The candidate patch extends the existing scenario; it does not alter production.
"""
from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

HEAD = "30ac68db8070705e07e5cd376fa155a9443be8ba"
MAIN_BLOB = "150d7fcae1065a51b2ce5f68cc8b51bfff5a7cfe"
TEST_BLOB = "fded421cee383870e3d62370521f0b4dfea01b3b"
MUTANTS = {
    "head": None,
    "stdin_disabled": (
        "if ((outfilename != NULL) && same_file(infile, outfilename)) {",
        "if ((outfilename != NULL) && (infile != stdin) && same_file(infile, outfilename)) {",
    ),
    "symlink_unfollowed": (
        "if (stat(outfilename, &sb_out))", "if (lstat(outfilename, &sb_out))",
    ),
    "devices_blocked": (
        "if (!S_ISREG(sb_in.st_mode) || !S_ISREG(sb_out.st_mode))\n\t\treturn (0);",
        "if (!S_ISREG(sb_in.st_mode) || !S_ISREG(sb_out.st_mode))\n\t\treturn (1);",
    ),
}
EXPECTED_EXPANDED_FAILURES = {"head": 0, "stdin_disabled": 6,
                              "symlink_unfollowed": 6, "devices_blocked": 1}


def require(ok: bool, message: str) -> None:
    if not ok:
        raise AssertionError(message)


def git_blob(data: bytes) -> str:
    return hashlib.sha1(f"blob {len(data)}\0".encode() + data).hexdigest()


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def check_scenario(root: Path, script: str, label: str, results: Path,
                   expected_total: int) -> dict:
    target = root / "tests/12-same-file.sh"
    target.write_text(script)
    env = dict(os.environ, N="12", VERBOSE="1", USE_VALGRIND="0")
    p = subprocess.run(["sh", "-x", str(root / "tests/test_scrypt.sh"),
                        str(root / "scrypt")], cwd=root, env=env,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       timeout=120, check=False)
    (results / f"{label}.log").write_bytes(p.stdout + p.stderr)
    trace = p.stderr.decode(errors="replace")
    descriptions = re.findall(r"^\+\s+_setup_check_description=(.*)$", trace, re.MULTILINE)
    prefix = re.findall(r"^\+\s+_check_ret=(-?\d+)\s*$", trace, re.MULTILINE)
    statuses = {i: int(v) for i, v in enumerate(prefix)}
    # Successful checks are removed by upstream. Its trace preserves the
    # checked prefix; remaining .exit files preserve the failed check and tail.
    for path in sorted((root / "tests-output").glob("*.exit")):
        match = re.search(r"-(\d+)\.exit$", path.name)
        require(match is not None, f"unexpected result path: {path}")
        index, value = int(match.group(1)), int(path.read_text().strip())
        require(index not in statuses or statuses[index] == value,
                f"trace/file disagreement at {label}/{index}")
        statuses[index] = value
    require(len(descriptions) == expected_total, f"{label}: setup count {len(descriptions)}")
    require(set(statuses) == set(range(expected_total)), f"{label}: missing result rows")
    rows = [{"index": i, "description": descriptions[i], "status": statuses[i]}
            for i in range(expected_total)]
    failures = [row for row in rows if row["status"] != 0]
    require(all(row["status"] in (0, 1) for row in rows), f"{label}: unexpected check status")
    return {"scenario": label, "rc": p.returncode, "total": expected_total,
            "passing": expected_total - len(failures), "failing": len(failures),
            "failures": failures, "checks": rows}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="Disposable built exact submitted checkout")
    parser.add_argument("results", type=Path)
    args = parser.parse_args()
    root, results = args.source.resolve(), args.results.resolve()
    results.mkdir(parents=True, exist_ok=True)
    actual = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
    require(actual == HEAD, f"wrong source revision: {actual}")
    main_source = (root / "main.c").read_text()
    original = (root / "tests/12-same-file.sh").read_text()
    require(git_blob(main_source.encode()) == MAIN_BLOB, "main source mismatch")
    require(git_blob(original.encode()) == TEST_BLOB, "native test source mismatch")
    require((root / "scrypt").is_file(), "build the exact source before replay")
    require(original.endswith("}\n"), "unexpected native scenario end")
    extension = (Path(__file__).parent / "alias-extension.inc").read_text()
    expanded = original[:-2] + extension + "}\n"
    patch = "".join(difflib.unified_diff(original.splitlines(keepends=True),
                                       expanded.splitlines(keepends=True),
                                       fromfile="a/tests/12-same-file.sh",
                                       tofile="b/tests/12-same-file.sh"))
    (results / "12-same-file-alias-extension.patch").write_text(patch)
    (results / "12-same-file-expanded.sh").write_text(expanded)
    subprocess.run(["sh", "-n", str(results / "12-same-file-expanded.sh")], check=True)
    report = {"source_head": HEAD, "source_main_blob": MAIN_BLOB,
              "source_test_blob": TEST_BLOB, "patch_sha256": digest(patch.encode()),
              "variants": [], "status": "INCOMPLETE"}
    with tempfile.TemporaryDirectory(prefix="kestrel-tau-428-mutants-") as tmp:
        for name, replacement in MUTANTS.items():
            work = Path(tmp) / name
            shutil.copytree(root, work, ignore=shutil.ignore_patterns(".git", "tests-output", "tests-valgrind"))
            mutant = main_source
            if replacement is not None:
                old, new = replacement
                require(main_source.count(old) == 1, f"{name}: mutation must match once")
                mutant = main_source.replace(old, new, 1)
            (work / "main.c").write_text(mutant)
            (results / f"{name}-source.patch").write_text("".join(difflib.unified_diff(
                main_source.splitlines(keepends=True), mutant.splitlines(keepends=True),
                fromfile="a/main.c", tofile=f"b/{name}/main.c")))
            with (results / f"{name}-build.log").open("wb") as log:
                subprocess.run(["make", "-j2"], cwd=work, stdout=log,
                               stderr=subprocess.STDOUT, check=True, timeout=120)
            native = check_scenario(work, original, f"{name}-native", results, 7)
            enhanced = check_scenario(work, expanded, f"{name}-expanded", results, 42)
            require(native["rc"] == 0 and native["failing"] == 0,
                    f"{name}: native scenario did not pass as predicted")
            expected = EXPECTED_EXPANDED_FAILURES[name]
            require(enhanced["failing"] == expected, f"{name}: expected {expected} failed assertions")
            require(enhanced["rc"] == (0 if expected == 0 else 1), f"{name}: wrong scenario exit")
            if name == "stdin_disabled":
                require(all(" stdin " in row["description"] for row in enhanced["failures"]), "wrong stdin findings")
            elif name == "symlink_unfollowed":
                require(all(" output-symlink " in row["description"] for row in enhanced["failures"]), "wrong symlink findings")
            elif name == "devices_blocked":
                require(enhanced["failures"][0]["description"] == "scrypt enc permits same null device", "wrong device finding")
            entry = {"variant": name, "main_blob": git_blob(mutant.encode()),
                     "binary_sha256": digest((work / "scrypt").read_bytes()),
                     "native": native, "expanded": enhanced}
            report["variants"].append(entry)
            print(json.dumps({"variant": name, "native_pass": native["passing"],
                              "native_total": 7, "expanded_pass": enhanced["passing"],
                              "expanded_fail": enhanced["failing"], "expanded_total": 42}), flush=True)
            (results / "mutation-report.json").write_text(json.dumps(report, indent=2) + "\n")
    require((root / "main.c").read_text() == main_source and
            (root / "tests/12-same-file.sh").read_text() == original,
            "source checkout was changed")
    report["status"] = "PASS"
    report["scenario_runs"] = 8
    report["assertion_outcomes"] = 196
    (results / "mutation-report.json").write_text(json.dumps(report, indent=2) + "\n")
    print("PASS: 8 scenario runs, 196 expected assertion outcomes, 3/3 targeted mutants detected", flush=True)


if __name__ == "__main__":
    main()
