# VERDICT-v0.7 Adversarial Results

**Date:** 2026-10-07
**Method:** 5 synthetic binaries designed to break VERDICT's assumptions. No GT — manual verification.

## Results

| Test | Pattern | O0 | O2 | Gap |
|------|---------|----|----|-----|
| a01_simd_shuffle | Different SIMD lane op | ✅ 4 targets | ❌ 0 | O2 uses different XMM idiom than p02 |
| a02_cmove_chain | 4-way cmove (not 2-way) | ✅ 4 targets | ❌ 0 | Chain length assumption |
| a03_multi_inherit | Two vptrs (A and B) | ⚠️ 2 targets | ❌ 0 | Only SLOT1, missing second vtable |
| a04_jump_table | Computed goto table | ❌ 0 | ❌ 0 | Indirect JUMPS not handled (only calls) |
| a05_double_indirect | FP via double pointer | ❌ 0 | ❌ 0 | Double indirection not tracked |

## Key Findings

1. **O0 > O2**: VERDICT handles unoptimized code better than optimized. The O2 patterns diverge from training cases.
2. **Indirect jumps are a blind spot**: VERDICT focuses on calls. Jump tables (common in switches) are not resolved.
3. **Double indirection**: `(*pp)()` where `pp` is `fp_t*` — VERDICT tracks single-level globals, not pointer-to-pointer.
4. **SIMD generality**: The p02 fix was pattern-specific, not general. Different shuffle ops break it.

## Implications for v0.8

These are not bugs — they're scope boundaries. Each requires a new analyzer:
- Jump table resolver (for a04)
- Multi-level pointer tracker (for a05)
- Generalized SIMD (for a01 O2)
- N-way cmove (for a02 O2)

**Priority for commercial use:** Jump tables (a04) are common in real binaries. This is the highest-value gap.
