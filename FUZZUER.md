# Fuzzing this tree with FuzzUEr

This repository is wired to [FuzzUEr](https://github.com/BreakingBoot/FuzzUEr), which fuzzes
UEFI firmware with an address sanitizer compiled into the firmware itself. The whole
integration is [`.github/workflows/fuzzuer.yml`](.github/workflows/fuzzuer.yml), and the part
that does the work is one `uses:` line.

## What it actually does

1. **Ports** the sanitizer into this checkout — ~81 new files and ~30 three-way merges into
   upstream code, repaired where upstream has moved.
2. **Builds** `OvmfPkg/OvmfPkgX64.dsc` with `-t CLANGSAN`, so loads and stores in firmware
   code are instrumented against a shadow map held in reserved memory.
3. **Generates a harness per protocol** from this tree's own headers — it reads the function
   signatures and the structs, so a protocol you added is fuzzed without anyone writing a
   harness for it.
4. **Fuzzes** each target under QEMU with libafl, snapshot-restoring between iterations.
5. **Triages** what the sanitizer reported, clusters it by site, and opens **one issue per
   candidate** with the source line, the crashing input and the log.

## Running it

| how | what happens |
|---|---|
| push a branch named `fuzzuer-anything` | qualifies the tree — port, build, instrument, detect — in minutes, spends no fuzzing budget and files no issues |
| push a branch named `fuzzuer-full-anything` | the whole pipeline on every target, findings filed as issues. Hours. This is the weekly run, on demand and without an API token |
| Actions → FuzzUEr → Run workflow | a full run; `targets`, `budget` and `qualify_only` are inputs |
| Sundays 05:00 UTC | a full run on `master` |

The branch push exists because it is the only entry point that needs no API token. A
workflow reachable *only* by `schedule` and `workflow_dispatch` can sit broken for a week
with nothing a developer could push to find out — which is exactly how a port regression
went unnoticed upstream until the next scheduled run.

## What it needs

- **A self-hosted Linux x64 runner registered to this repository.** A runner registered to
  another repository will not pick this up, and the symptom is a job that sits in `Queued`
  with nothing explaining why.
- **~100 GB free disk.** The first run builds LLVM-instrumented OVMF and a QEMU that libafl
  compiles from source, which takes hours; later runs reuse the images.
- **`contents: write` and `issues: write`.** `issues: write` files the findings;
  `contents: write` pushes the `fuzzuer-evidence` branch that carries each finding's harness,
  crashing input and log. A read-only token fuzzes perfectly well and then loses every
  finding at the last step.

Only `OvmfPkg/OvmfPkgX64.dsc`, `-a X64`, `-t CLANGSAN` is built. No other DSC, architecture
or toolchain.

## Reading a finding

**Findings are candidates, not confirmed vulnerabilities.** Each issue carries the bug class,
the module, the source file and line, a snippet around the crash site, and links to the
harness, the input and the log on the `fuzzuer-evidence` branch. Before acting on one:

- Check the **module** column. A report attributed to a library names the library, not the
  caller that passed it bad data — the issue body lists the callers the static analysis found
  crossing into it, and that is usually where the fix belongs.
- A **double-fetch** finding names the comm-buffer field that was read twice, both read sites,
  and the struct it belongs to. Re-reading a caller-controlled field is only a defect when the
  value can change in between, so read the validation path before filing it as one.
- A finding **present on every boot** rather than driven by an input is in a different section
  of `bugs.md`; those are usually firmware doing something legitimate, but not always.

Issues are keyed on module + bug class + source file, so a later run that finds the same site
again adds nothing. The build offset is deliberately left out of that key, because an offset
moves with every build and would file a fresh issue every week for a defect already open.
