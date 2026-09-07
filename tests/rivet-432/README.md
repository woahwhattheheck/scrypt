# RIVET — scrypt PR 432 review and native assertion correction

Completed September 6, 2026 (America/Chicago). RIVET is a ChatGPT LLM session.
This is a review and test-improvement handoff, not an independent bounty claim.
The original report, implementation, and sponsor follow-through remain with D.

## Delivered

The minimal test correction is **fork-only PR 2**:
https://github.com/woahwhattheheck/scrypt/pull/2

- Base: `3fcb6826f01157682038036fcea2620b3509a12c`
- Final head: `8094c076532d5be16f5b3a2f29d25ceb4178af64`
- Changed file: `tests/08-passphrase-file.sh`, four additions, three deletions.
- Final tested file blob: `44ce960acd7b6113920a5ed64b78f27300a9c96f`.

The PR gives missing-passphrase and wrong-passphrase cases distinct output paths
and checks the exact paths those commands used. The previous checks examined a
file that neither failing command targeted. The target implementation branch
was not changed or merged. No upstream issue, PR, or sponsor message was sent.

## Original PR 432: completed validation

Upstream: https://github.com/Tarsnap/scrypt/pull/432

- Original base: `a71ae8281742ac638bc75baa4334f2292251e0eb`
- Submitted head: `3fcb6826f01157682038036fcea2620b3509a12c`
- Base reader blob: `4379a61d72bc5d1224ec354fdba2a1fb65cac930`
- Submitted reader blob: `1f0cd35f2b4c489784c3ab1dbbd33b7272eee522`

Local Linux/GCC 14.2: **48/48 expected reader outcomes**, using the actual reader,
logging, and memory-zeroing sources. All seven source blobs were checked against
GitHub. AddressSanitizer, UndefinedBehaviorSanitizer, leak detection, and strict
compiler warnings were enabled. Six malformed carriage-return forms distinguish
the fix; valid line endings, empty files, length boundaries and error controls
retain their expected behavior. Full logs and exact commands are in `results/`.

Hosted run: https://github.com/woahwhattheheck/scrypt/actions/runs/34068494145
Job: `101581393970`. Validation commit:
`3ae6dd8bf652b1da1e32be0d05957d19b494ae90`.

Ubuntu 24.04.4 / GCC 13.3.0 / OpenSSL 3.0.13: both complete application builds
passed `autoreconf -i`, `./configure`, and `make -j2`. The exact submitted native
scenario (blob `ff4df75f61599009e870faa4c73f253870f841cb`) was then run against
both binaries. The original fails exactly the three new stray-CR checks and
actually decrypts the reference with the truncated password prefix. The patched
binary passes all 13 checks and creates no output for that rejected input.
The hash-pinned Git-object reader runner also passes 48/48 in this environment.

Hosted evidence artifact: `9999712108`, 99 files, ZIP SHA256:
`4b2e053fc4515818185b45643f355c4c31f9ccf04886f80176f2a5570b04305a`.

## Test correction: executed mutation validation

Run: https://github.com/woahwhattheheck/scrypt/actions/runs/34068644940
Job: `101581816052`. Validation commit:
`84df1995d8cce292d7c1636f5b5e60ba2eba5aa6`.

**8/8 expected scenario outcomes** were verified with the real built executable.
The original and corrected native scenarios each run in four modes: clean,
output injected after missing-passphrase rejection, output injected after
wrong-passphrase rejection, and both errors. The wrapper calls the real scrypt
binary and preserves its exit status and diagnostics, then deliberately writes
a marker only inside its temporary case directory.

Both clean controls pass all 13 native checks. The old assertions incorrectly
pass all three erroneous-output modes. The corrected assertions fail exactly
the applicable no-file checks. This is a demonstrated test-coverage defect;
the erroneous file writes are **synthetic**, not observed scrypt behavior.

Hosted evidence artifact: `9999754281`, 148 files, ZIP SHA256:
`b860c2d89c32ffc502b95658c960ba589e42e5934edf9a2c68544899741d9fa4`.

## Replay

The source-hash-pinned helpers and isolated workflows are in the review branch:
https://github.com/woahwhattheheck/scrypt/tree/84df1995d8cce292d7c1636f5b5e60ba2eba5aa6/tests/rivet-432

From that repository with pinned Git objects present:

```sh
python3 tests/rivet-432/run.py --repo . --output /tmp/rivet-reader-results
python3 tests/rivet-432/native.py --base /path/to/built-base --head /path/to/built-head --output /tmp/rivet-native-results
python3 tests/rivet-432/negative_outputs.py --built /path/to/built-head --patch tests/rivet-432/negative-output-targets.patch --output /tmp/rivet-assertion-results
```

The native runners require already-built, isolated worktrees. The first native
runner copies the submitted test into the base worktree but checks that the
implementation bytes remain unchanged. The assertion runner uses temporary
copies. The workflows show the full pinned build recipe. Take the minimal fork
PR or patch to integrate the correction, not the whole validation branch.

In the portable evidence archive, replay the local reader test without network:

```sh
python3 tests/run.py --sources sources --output replay-results
```

## Scope and limits

Only generated fixtures were used; no real passwords, user files or production
services were accessed. Embedded-NUL truncation remains observable on both
reader revisions. It is not new in PR 432, not fixed here, and not a separate
report or reward claim. This work does not certify arbitrary binary passwords,
all failure interleavings, non-Linux platforms, or the full project test suite.
The full application builds and focused native scenarios are distinct from
`make test` across every scenario, which was not run.

The review result and minimal-fix handoff are recorded in the existing Slack
coordination and bounty threads. No unattended monitoring is running.
