# Third-Party Notices

## OWASP Agent Memory Guard

Repository: <https://github.com/OWASP/www-project-agent-memory-guard>

Inspected branch and commit: `main` at
`93bc011d54ae3495718ab5d59aef0aaa05e70264` on 2026-07-15.

License: Apache License 2.0.

The repository was used as prior art and a research comparison. The initial
Verity Cordon implementation is clean-room and does not copy donor source. If a
future file is copied, adapted, or substantially derived, that file must retain
the applicable notices, identify the exact source commit, and be marked as
modified.

## Trojan Hippo Research and Benchmark

Paper: <https://arxiv.org/abs/2605.01970>

Repository: <https://github.com/debesheedas/trojan-hippo-benchmark>

Inspected branch and commit: `main` at
`a67d3261338120c606fcf6afda2547f622809922` on 2026-07-15.

Repository license: Apache License 2.0. Paper distribution license: CC BY 4.0.

These sources informed the delayed-trigger persistent-memory threat model only.
They are not runtime dependencies, and the benchmark is not vendored, imported,
executed, or reproduced by Verity Cordon. No benchmark source, dataset, prompt,
simulated-email implementation, or reported result was copied. Verity's fixed
synthetic documentation response, inert local sink, marker values, tests, and
demo narrative are original clean-room materials. Verity therefore describes
the scenario as Trojan Hippo-inspired and does not claim benchmark
compatibility, comparative performance, or the paper's attack-success rates.

Python and JavaScript dependencies retain their respective upstream licenses;
the lockfiles provide the exact resolved package set.
