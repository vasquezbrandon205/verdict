# VERDICT — Precision Binary Analysis Engine

**VERDICT** = **VER**ified **I**n**D**irect **C**all **T**argets.

*Independent research project by Brandon Manuel Vasquez. Not affiliated with Muse AI (Meta's AI assistant) or any similarly named product.*

**VERDICT** resolves indirect calls in stripped binaries with zero false positives and evidence for every claim. When it doesn't know, it says UNKNOWN instead of guessing.

Zero Ghidra dependency: custom ELF loader, Capstone decoder, built-from-scratch CFG.

## What it does

- **Indirect call resolution**: recovers targets of `call *%reg`, vtables, SIMD tables, cross-module callbacks
- **Zero false positives**: P=1.000 on the benchmark corpus, verified by all-sites FP accounting (not just benchmark targets)
- **Evidence chains**: every target carries provenance (`DATAFLOW`, `VTABLE_SLOTn`, `SIMD_TABLE`, `INTERPROC_PARAMn`, `XMOD`, …)
- **Honest uncertainty**: explicit UNKNOWN with reasons, not silent misses

## Benchmark

12 C/C++ programs (p01–p12) covering direct function pointers, jump tables, structs, callbacks, switches, computed gotos, C++ vtables, tail calls, cross-module callbacks, signal handlers, and global function pointers. Compiled with GCC 13.3.0 at O0/O2/O3, stripped (with DWARF twins for ground truth). **36 indirect call sites, 72 target relations.** Ground truth by construction, frozen before analysis.

Two scorers, reported side by side:

| Engine | Scorer | P | R | F1 | TP | FP | FN |
|--------|--------|---|---|----|----|----|----|
| VERDICT v0.7 | RANGE (target in function range) | 1.000 | 1.000 | 1.000 | 72 | 0 | 0 |
| VERDICT v0.7 | STRICT (exact entry address) | 1.000 | 1.000 | 1.000 | 72 | 0 | 0 |
| Ghidra 12.1.4 | RANGE | 1.000 | 0.444 | 0.615 | 32 | 0 | 40 |
| Ghidra 12.1.4 | STRICT | 0.969 | 0.431 | 0.596 | 31 | 1 | 41 |

Ghidra resolves a target iff intraprocedural constant propagation suffices — and silently omits the rest. It misses memory-indirect tables, global function pointers, interprocedural FP parameters, cross-module callbacks, and vtable slots > 0. VERDICT resolves all of these through specialized analyzers (see `PAPER.md` §5.2).

The STRICT row matters: one of Ghidra's RANGE "hits" (p02 `0x101270`) lands mid-function rather than on the exact entry, so it counts as a miss under strict scoring. We report both so nobody has to take our word for which scorer flatters whom.

## Quick start

```bash
pip install capstone

# CLI
python3 verdict_cli.py /bin/ls

# API server
python3 verdict_api.py 8080
curl -X POST --data-binary @/bin/ls http://localhost:8080/analyze
```

## Architecture

```
verdict_cli.py / verdict_api.py    # Interfaces (v0.9)
        ↓
batch.py                     # Orchestration
        ↓
dataflow.py                  # Kill-aware register/global/stack dataflow
├── vtable.py                # C++ vtable slot resolution
├── simd.py                  # XMM lane tracking for vectorized tables
├── interproc.py             # Cross-function FP parameter inference
└── xmod.py                  # Cross-module (main ↔ shared library)
        ↓
foundation.py                # ELF loader, Capstone decoder, CFG
```

Supporting modules: `verdict_score.py` / `verdict_score_strict.py` (benchmark scorers), `gen_adversarial.py` (adversarial corpus generator), `ghidra_verdict_import.py` (import VERDICT results into Ghidra as annotations).

## Honest limitations

- **x86-64 Linux only** (ARM64 decoder ready, needs test corpus)
- **ICF-focused** (not a full decompiler)
- **Conservative on real-world binaries** — high UNKNOWN rate by design. On `/bin/ls`: 29 sites, 1 resolved with evidence, 28 UNKNOWN
- **O2 adversarial gaps** (see `ADVERSARIAL-RESULTS.md`): optimized SIMD idioms, 4-way cmove chains, indirect jumps, double indirection
- **Micro-benchmark**: 36 sites is small; real-world validation is preliminary
- Not a Ghidra replacement — it's the precision layer Ghidra is missing

## Methodology

Falsification-driven: ground truth frozen before analysis, negative results reported (v0.1's "beats Ghidra" hypothesis was falsified before v0.5 earned it), adversarial corpus targeting our own assumptions. Every claim has a benchmark; every benchmark ships its scorer. See `PAPER.md`.

## What's in `data/`

The 36 per-binary prediction files from the benchmark run — every site VERDICT discovered, its predicted targets, confidence, and evidence codes (or explicit UNKNOWN). Independent re-scoring welcome.

## License

MIT — see `LICENSE`.

## Citation

```bibtex
@software{vasquez2026verdict,
  author  = {Brandon Manuel Vasquez},
  title   = {VERDICT: Evidence-First Indirect Control Flow Recovery},
  version = {0.9.0},
  date    = {2026-10-11},
  url     = {https://github.com/vasquezbrandon205/verdict}
}
```

See `CITATION.cff`.
