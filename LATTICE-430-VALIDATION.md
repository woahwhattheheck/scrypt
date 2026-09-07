# LATTICE: scrypt PR 430 validation

Independent test-only support for [Tarsnap/scrypt PR 430](https://github.com/Tarsnap/scrypt/pull/430). Original report, implementation, and sponsor ownership remain with D. No duplicate upstream report or PR was submitted by this validation lane.

## Executed result

**56 of 56 expected outcomes matched**, including expected failures on the unfixed base. These are not 56 independent regression scenarios.

[GitHub Actions run 34068534532](https://github.com/woahwhattheheck/scrypt/actions/runs/34068534532), job 101581508154, executed on September 7, 2026, 00:02–00:03 UTC (September 6 in US Central/Eastern time). Tested review commit: `70f9fe86e8102e99c7e088c414b03d116b68e4e7`. This document was added after execution; no test or production source was changed for the receipt.

Environment: Ubuntu 24.04.4 LTS x86-64, GCC 13.3.0, Valgrind 3.22.0. The observed expanded-key allocator used the AES-NI backend.

| Scope | Observed result |
|---|---|
| Two exact-revision full builds | Both `autoreconf -fi`, `./configure CFLAGS=-O1 -g3 -fno-omit-frame-pointer`, and `make -j2` passed. Production source SHA256 unchanged during each build. |
| Ten base write failures | One definitely-lost 272-byte allocation per invocation. Stack includes `crypto_aes_key_expand_aesni`, `crypto_aes_key_expand`, and the corresponding `scryptenc_file` or `scryptdec_file_copy`. |
| Ten patched write failures | Intended application status 1 and output-write diagnostic; no Valgrind memory records. |
| Twenty normal enc/dec commands | Status 0; no Valgrind memory records. |
| Ten round trips | Decrypted bytes exactly match generated inputs. |
| Submitted native scenario, memory mode off | Both base and head pass. Exit-code-only checks do not distinguish this leak. |
| Submitted native scenario, `USE_VALGRIND=1` | Base fails with native harness status 108 and the expanded-key leak; head passes with status 0. |

Count: 2 build checks + 40 memory-checked program commands + 10 round-trip comparisons + 4 native-scenario mode checks = 56 checked outcomes.

Inputs: deterministic public fixture bytes, sizes 8193, 65535, 65536, 65537, and 131073. Failure output was Linux `/dev/full`; no production files, secrets, or live accounts were used. Real encryption/decryption and real file I/O were exercised, not mocked crypto or translated snippets.

## Exact provenance

| Item | Value |
|---|---|
| Base commit | `a71ae8281742ac638bc75baa4334f2292251e0eb` |
| Submitted PR head | `ed46fc642108434ab16a53f5e8bc252435242825` |
| Base `lib/scryptenc/scryptenc.c` Git blob | `0ae83c58d78173f90a8daefe7c7bfe3a052687c5` |
| Head source Git blob | `2189ae67c40312631e860e08f79caea778c9bd90` |
| Base source SHA256 | `1cbe3cf13eae8024bf48d86a531ab8b44f564cc0de69728645b6422f6d837c73` |
| Head source SHA256 | `ceb82032734db1098d4b47e257bf59cb2c195e647e39e5f4b84cdf6c38b42a27` |
| Validation code/workflow commit | `70f9fe86e8102e99c7e088c414b03d116b68e4e7` |
| Evidence artifact ID | `9999730717` |
| Evidence ZIP SHA256 | `d8e350ca15d57175d79073e20f8e54ab9aa85a30f3d3407e1c00aa755406086e` |

[Raw evidence artifact](https://github.com/woahwhattheheck/scrypt/actions/runs/34068534532/artifacts/9999730717): 587573 bytes, 198 files. Contains stdout/stderr, build logs, native harness output, Valgrind XML allocation stacks, manifest, results, and summary. The downloaded ZIP was independently hash-checked. GitHub artifact retention expires September 21, 2026 UTC; this report and runner remain in Git.

## Replay

Use a Linux Git checkout containing the two pinned commits and this review branch. Install a C toolchain, OpenSSL development files, Autoconf/Automake/Libtool, autoconf-archive, Python supporting tar extraction filters, and Valgrind. `/dev/full` must exist as a character device.

```sh
python3 tests/lattice-430/run.py /absolute/path/to/new-results-directory
```

The output directory must not already exist. The runner archives and builds both exact revisions in isolated temporary directories. It uses the submitted head's unchanged `tests/test_scrypt.sh` and `tests/13-write-error.sh` against each resulting binary, once with memory checks off and once with `USE_VALGRIND=1`.

The independent per-invocation Valgrind checks assert the allocation stack, error type, application diagnostic, and expected exit status. They use no custom suppressions. The separate native harness uses its own upstream suppression setup and result convention.

## Scope and limitations

This supports the two submitted write-error cleanup changes and establishes which native test mode detects their absence. It does not cover the complete `make test` suite, non-Linux platforms, ARM or software AES, later partial-output failures after successful disk writes, allocation-failure injection, or security impact. No maintainer acceptance, merge, bounty award, or payment is inferred from the passing review. The original implementation branch was not modified.
