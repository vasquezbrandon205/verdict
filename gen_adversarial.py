#!/usr/bin/env python3
"""VERDICT-v0.7 adversarial corpus generator.
Creates binaries with patterns designed to break VERDICT's assumptions.
Each test targets a specific VERDICT mechanism.
"""
import os, subprocess, json, textwrap

BASE = os.path.dirname(os.path.abspath(__file__))
CORPUS = os.path.join(BASE, 'adversarial')
os.makedirs(CORPUS, exist_ok=True)

TESTS = {
    # A1: SIMD with different lane arrangement (shufps instead of punpcklqdq)
    'a01_simd_shuffle': r'''
        typedef void (*fp_t)(void);
        void t1(void) {} void t2(void) {} void t3(void) {} void t4(void) {}
        fp_t table[4] = {t1, t2, t3, t4};
        int idx;
        __attribute__((noinline)) void dispatch(void) {
            // Force different SIMD pattern via manual shuffle
            fp_t local[4];
            __builtin_memcpy(local, table, sizeof(local));
            local[idx]();
        }
        int main() { idx = 2; dispatch(); return 0; }
    ''',
    # A2: Deep cmove chain (4-way, not 2-way like p12)
    'a02_cmove_chain': r'''
        typedef void (*fp_t)(void);
        void w1(void) {} void w2(void) {} void w3(void) {} void w4(void) {}
        fp_t g_fp;
        int c1, c2;
        __attribute__((noinline)) void setup(void) {
            fp_t f = w1;
            if (c1) f = w2;
            if (c2) f = w3;
            else f = w4;
            g_fp = f;
        }
        int main() { c1 = 1; c2 = 0; setup(); g_fp(); return 0; }
    ''',
    # A3: Vtable with multiple inheritance (two vptrs)
    'a03_multi_inherit': r'''
        struct A { virtual void fa() {} virtual void ga() {} };
        struct B { virtual void fb() {} virtual void gb() {} };
        struct C : A, B { void fa() override {} void fb() override {} };
        __attribute__((noinline)) void call_a(A* p) { p->ga(); }
        __attribute__((noinline)) void call_b(B* p) { p->gb(); }
        int main() { C c; call_a(&c); call_b(&c); return 0; }
    ''',
    # A4: Indirect jump table (switch with computed goto)
    'a04_jump_table': r'''
        void t1(void) {} void t2(void) {} void t3(void) {}
        int idx;
        __attribute__((noinline)) void dispatch(void) {
            static void* table[] = {&&l1, &&l2, &&l3};
            goto *table[idx];
            l1: t1(); return;
            l2: t2(); return;
            l3: t3(); return;
        }
        int main() { idx = 1; dispatch(); return 0; }
    ''',
    # A5: FP stored through double indirection
    'a05_double_indirect': r'''
        typedef void (*fp_t)(void);
        void target(void) {}
        fp_t *pp;
        fp_t g;
        __attribute__((noinline)) void setup(void) {
            g = target;
            pp = &g;
        }
        __attribute__((noinline)) void fire(void) {
            (*pp)();
        }
        int main() { setup(); fire(); return 0; }
    ''',
}

def main():
    manifest = {}
    for name, src in TESTS.items():
        cpath = os.path.join(CORPUS, name + '.c')
        open(cpath, 'w').write(textwrap.dedent(src))
        built = []
        for opt in ['O0', 'O2']:
            bpath = os.path.join(CORPUS, f'{name}_{opt}')
            r = subprocess.run(
                ['gcc', f'-{opt}', '-o', bpath, cpath, '-no-pie'],
                capture_output=True, text=True
            )
            if r.returncode == 0:
                # Strip a copy
                spath = bpath + '_stripped'
                subprocess.run(['cp', bpath, spath])
                subprocess.run(['strip', spath])
                built.append(opt)
            else:
                print(f"FAIL {name} {opt}: {r.stderr[:200]}")
        manifest[name] = {'built': built, 'target': 'VERDICT adversarial'}
        print(f"{name}: built {built}")

    json.dump(manifest, open(os.path.join(CORPUS, 'MANIFEST.json'), 'w'), indent=1)
    print(f"\nCorpus in {CORPUS}")

if __name__ == '__main__':
    main()
