# KESTREL-TAU: scrypt PR 428 validation receipt

Review-only contribution, completed September 6, 2026 US Central / September 7 UTC. Original D retains implementation, report and sponsor ownership. No upstream comment, duplicate issue, PR, merge, award or payment is claimed by this review.

## Exact source and replay revisions

Target: https://github.com/Tarsnap/scrypt/pull/428

- Application baseline: `a71ae8281742ac638bc75baa4334f2292251e0eb`.
- Submitted application head: `30ac68db8070705e07e5cd376fa155a9443be8ba`.
- Baseline `main.c` blob: `2b05e252f92af7ace15b2b54470b75535330e352`.
- Submitted `main.c` blob: `150d7fcae1065a51b2ce5f68cc8b51bfff5a7cfe`.
- Isolated review branch: `review/kestrel-tau-428-validation-20260906` in `woahwhattheheck/scrypt`.
- Corrected replay/tooling commit: `e7f867f3760083bf60863b86405042dfcae0d10b`.

The review adds only replay tooling, a fork-only workflow and this receipt. It does not edit the original implementation branch. Full application builds used `autoreconf -fi`, `./configure`, and `make -j2`; the workflow verified the `main.c` blob against each pinned tree before and after building.

## Verified results

The first run produced **152 asserted matrix outcomes: 76 per revision**. Every emitted row follows its case's assertions. The matrix covered 54 alias cases, 16 distinct-file roundtrip controls, four `/dev/null` controls and two pre-passphrase-order checks on each revision.

Alias coverage: same pathname, hard link, input symlink, output symlink, `..` spelling, stdin to the same path, stdin to a hard link, stdin to a symlink, and stdin to `/dev/stdin`; encryption and decryption; plaintext lengths 0, 257 and 65,537 bytes. Generated fixture names also contain spaces and a dollar sign; no shell evaluation is used for those commands.

On the baseline, all 27 encryption alias cases exit 0 and overwrite input with a 128-byte ciphertext. A real decrypt of each resulting ciphertext confirms it encrypts empty input. Baseline decryption is different because the application processes the header before opening output and stdio may buffer input: the 0-byte and 257-byte plaintext fixtures decrypt in place and exit 0, replacing the original ciphertext. The 65,537-byte plaintext fixture exits 1 only after overwriting its ciphertext with 3,968 plaintext bytes.

On the submitted head, **all 54 alias cases exit 1 with the intended same-file diagnostic and preserve input bytes, inode and permissions**. The 20 distinct-file/device controls per revision work as expected, including identical contents in different inodes, existing independent output, dangling and existing-target output symlinks, stdin/stdout, and `/dev/null`. Both ordering cases show the head rejects a same-file operation before trying a deliberately missing password file.

The unchanged submitted native scenario `tests/12-same-file.sh` was also executed against both actual binaries. In the corrected collector run, baseline has **1/7 passing checks** (all six safety checks fail); submitted head has **7/7 passing checks**. These are 14 observed before/after check outcomes, not 14 checks that both revisions pass.

Environment: Ubuntu 24.04 hosted x86_64; GCC 13.3.0; glibc 2.39; Python 3.12.3; Linux 6.17.0-1022-azure.

## Evidence and transparent harness correction

Initial run: https://github.com/woahwhattheheck/scrypt/actions/runs/34068636186

Artifact ID `9999754491`, filename `kestrel-tau-428-evidence.zip`, SHA256 `2358dac45fcf977cef264fd3efbe07568262c5f20c7e4be45b2dc4409219ceb7`.

This run's raw `replay.log` contains the complete 152-row passing matrix. **Its overall green workflow status is not a clean replay pass:** after native testing, my collector incorrectly expected successful `.exit` files to remain, although upstream deletes them. The `tee` pipeline hid that collector exception. The raw artifact preserves the exception; it is not discarded or relabeled.

Corrected run: https://github.com/woahwhattheheck/scrypt/actions/runs/34068857899

Artifact ID `9999818713`, filename `kestrel-tau-428-native-corrected-evidence.zip`, SHA256 `8b7f5886c47aa27ee4161df5a293493fa472df437b42122ab4136bc7064455e8`.

The correction reads the native harness's exact shell trace after successful cleanup, uses an explicit fail-closed Bash pipeline and verifies an intentionally failing child exits through `tee` with status 17. The corrected run rebuilt both pinned revisions and reran **only the native scenario and corrected collector**; it did not repeat the sealed 152-case matrix. Its `report.json` records `status=PASS`, `native_only=true`, `matrix_outcomes=0`, and `native_check_outcomes=14`. Both downloaded ZIP digests were independently verified, as were the seven native head trace results and pipeline-failure probe.

The combined result is the original matrix evidence plus the corrected native evidence, not a claim that the second run repeated all tests. GitHub artifact retention is 14 days; preserve the downloaded ZIPs for longer-lived evidence.

## Replay

Use disposable, built checkouts at the exact baseline and submitted head, and Python 3.10 or later. The native runner uses the checkouts' `tests-output` directories and removes prior test output there. Application inputs are generated only inside a temporary directory. No production files, credentials or external services are used.

```sh
python3 tests/kestrel-tau-428/validate.py /path/to/base /path/to/head /path/to/evidence
# Focused native replay without repeating the static matrix:
python3 tests/kestrel-tau-428/validate.py --native-only /path/to/base /path/to/head /path/to/evidence
```

## Boundaries

This validates static same-file aliases on the tested Linux runtime, not atomic protection against concurrent path substitution after the precheck. It cannot prevent shell redirection from truncating a file before the program starts. No other-platform, ASan, UBSan, Valgrind, full `make check`, or production-workload result is claimed. The existing sponsor and implementation owner decides whether and how to cite this evidence upstream.
