import hashlib
import json
import os
from pathlib import Path
import resource
import subprocess
import sys
import tempfile

before = Path(sys.argv[1]).resolve()
after = Path(sys.argv[2]).resolve()
expected_error = b"Input and output files are the same"
root = Path(tempfile.mkdtemp(prefix="scrypt-stdout-"))
password = root / "passphrase"
password.write_text("synthetic-stdout-regression\n")
plain = b"stdout alias regression\n" * 32
results = []

def limits():
    resource.setrlimit(resource.RLIMIT_FSIZE, (65536, 65536))
    resource.setrlimit(resource.RLIMIT_CPU, (5, 5))

def run(binary, mode, source, output=None, stdout=None, stdin=None):
    command = [str(binary), mode]
    if mode == "enc":
        command += ["--logN", "10", "-r", "1", "-p", "1"]
    command += ["--passphrase", "file:" + str(password), str(source)]
    if output is not None:
        command.append(str(output))
    return subprocess.run(command, stdin=stdin, stdout=stdout or subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=10, preexec_fn=limits)

seed = root / "seed"
seed.write_bytes(plain)
encrypted = root / "encrypted"
seed_result = run(before, "enc", seed, encrypted)
assert seed_result.returncode == 0, seed_result.stderr
cipher = encrypted.read_bytes()

for phase, binary in (("before", before), ("after", after)):
    for mode, content in (("enc", plain), ("dec", cipher)):
        for input_kind in ("file", "stdin"):
            target = root / (phase + "-" + mode + "-" + input_kind)
            target.write_bytes(content)
            with target.open("rb") as input_file, target.open("ab") as output_file:
                completed = run(binary, mode, "-" if input_kind == "stdin" else target,
                    stdout=output_file, stdin=input_file)
            unchanged = target.read_bytes() == content
            record = {"phase": phase, "mode": mode, "input": input_kind,
                "returncode": completed.returncode, "unchanged": unchanged,
                "input_bytes": len(content), "output_bytes": target.stat().st_size,
                "same_file_message": expected_error in completed.stderr}
            results.append(record)
            print(json.dumps(record), flush=True)
            if phase == "after":
                assert completed.returncode == 1 and unchanged, record
                assert expected_error in completed.stderr, record
            else:
                assert not unchanged, record

# Different standard-output files still encrypt and decrypt normally.
normal_cipher = root / "normal-cipher"
with normal_cipher.open("wb") as output_file:
    completed = run(after, "enc", seed, stdout=output_file)
assert completed.returncode == 0, completed.stderr
normal_plain = root / "normal-plain"
with normal_cipher.open("rb") as input_file, normal_plain.open("wb") as output_file:
    completed = run(after, "dec", "-", stdout=output_file, stdin=input_file)
assert completed.returncode == 0 and normal_plain.read_bytes() == plain
results.append({"control": "independent-stdout-roundtrip", "passed": True})

# Existing named-output and character-device behavior is retained.
named = root / "named"
named.write_bytes(plain)
completed = run(after, "enc", named, named)
assert completed.returncode == 1 and named.read_bytes() == plain
assert expected_error in completed.stderr
results.append({"control": "named-output-alias", "passed": True})
completed = run(after, "enc", "/dev/null", "/dev/null")
assert completed.returncode == 0, completed.stderr
results.append({"control": "named-null-device", "passed": True})
with open("/dev/null", "rb") as input_file, open("/dev/null", "wb") as output_file:
    completed = run(after, "enc", "-", stdout=output_file, stdin=input_file)
assert completed.returncode == 0, completed.stderr
results.append({"control": "stdin-stdout-null-device", "passed": True})
summary = {"baseline_commit": "14db0e0600340f8254fe602fd07e25a8fe3f59ad",
    "executed_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
    "source_blob": subprocess.check_output(["git", "hash-object", "main.c"], text=True).strip(),
    "test_blob": subprocess.check_output(["git", "hash-object", "tests/12-same-file.sh"], text=True).strip(),
    "compiler": subprocess.check_output(["cc", "--version"], text=True).splitlines()[0],
    "results": results}
print("SCRYPT_STDOUT_RECEIPT=" + json.dumps(summary), flush=True)
