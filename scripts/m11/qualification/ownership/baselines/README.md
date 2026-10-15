# Baseline custodian fixtures

Exact bytes of earlier custodian revisions, used only by the before/after witnesses in
`run_tests.sh` (which pins their sha256). Committed so the witnesses run without
repository history, for example in the public CI export.

| directory | source commit | path in that commit |
|---|---|---|
| `round2/` | `f4622f5ba594fbbff72c7cdf004a1f4e73c8ac85` | `scripts/m11/qualification/ownership/m11_custodian.{c,h}` |
| `round3-pre-w1b/` | `9cbcb9f242424495eaac22aea7ddf5e86f9ccc23` | `scripts/m11/qualification/ownership/m11_custodian.{c,h}` |

`../verify_baselines.py` re-extracts each file with `git show` and requires identical
bytes. Never edit these files; a new baseline gets a new directory.
