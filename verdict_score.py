#!/usr/bin/env python3
"""Scorer for VERDICT-v0.1 output vs GT. Addresses are in binary vaddr space (no base offset)."""
import json, os, re, subprocess, sys, math
from collections import defaultdict

BASE = os.path.dirname(os.path.abspath(__file__))
BLD = os.path.join(BASE, '..', 'icf-experiment', 'build')
GT = json.load(open(os.path.join(BASE, '..', 'icf-experiment', 'corpus', 'GT.json')))

def nm_map(dwarf_bin):
    out = subprocess.run(['nm', '-C', '--defined-only', dwarf_bin],
                         capture_output=True, text=True).stdout
    syms = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[1] in 'TtWw':
            addr = int(parts[0], 16)
            name = ' '.join(parts[2:])
            short = re.sub(r'\(.*\)', '', name).strip()
            syms.append((addr, short, name))
    syms.sort()
    m = {}
    for i, (addr, short, name) in enumerate(syms):
        end = syms[i + 1][0] if i + 1 < len(syms) else addr + 0x1000
        m[short] = (addr, end)
        m[name] = (addr, end)
    return m

def gt_ranges(prog, site, nm):
    ranges = set()
    for t in site['targets']:
        for name, (s, e) in nm.items():
            if name == t or (t in name and name.startswith(t)):
                ranges.add((s, e))
                break
    return ranges

def main():
    resdir = sys.argv[1]
    rows = []
    for prog, pinfo in GT['programs'].items():
        for opt in ['O0', 'O2', 'O3']:
            if prog == 'p10':
                dwarf_bin = os.path.join(BLD, f'libp10_{opt}_dwarf.so')
                tag = f'verdict_libp10_{opt}_stripped'
                nm = nm_map(dwarf_bin)
                nm_main = nm_map(os.path.join(BLD, f'p10_{opt}_dwarf'))
                for k, v in nm_main.items():
                    nm.setdefault(k, v)
            else:
                dwarf_bin = os.path.join(BLD, f'{prog}_{opt}_dwarf')
                tag = f'verdict_{prog}_{opt}_stripped'
                nm = nm_map(dwarf_bin)
            mpath = os.path.join(resdir, tag + '.json')
            if not os.path.exists(mpath):
                continue
            verdict = json.load(open(mpath))
            # match VERDICT sites to GT sites by address range
            for site in pinfo['sites']:
                if site.get('kind') not in ('indirect_call', 'virtual_call'):
                    continue
                sf = site['func']
                src_range = None
                for nname, (a, e) in nm.items():
                    if nname == sf or (sf in nname and nname.startswith(sf)):
                        src_range = (a, e)
                        break
                if src_range is None:
                    continue
                cands = [s for s in verdict['results']
                         if src_range[0] <= int(s['site_addr'], 16) < src_range[1]]
                cands.sort(key=lambda s: int(s['site_addr'], 16))
                siblings = [x for x in pinfo['sites']
                            if x['func'] == sf and x.get('kind') in ('indirect_call', 'virtual_call')]
                ordinal = siblings.index(site)
                if ordinal >= len(cands):
                    # VERDICT missed the site entirely
                    rows.append((prog, opt, site['id'], sf, gt_ranges(prog, site, nm),
                                 set(), None, None, 'MISSED_SITE'))
                    continue
                ms = cands[ordinal]
                gt = gt_ranges(prog, site, nm)
                mset = set(int(x, 16) for x in ms['targets'])
                rows.append((prog, opt, site['id'], sf, gt, mset,
                             ms['confidence'], ms['evidence'], ms['site_addr']))

    # metrics
    def site_scores(gt_ranges, rep):
        hits = {a for a in rep if any(s <= a < e for s, e in gt_ranges)}
        misses = set(rep) - hits
        gt_hit = {r for r in gt_ranges if any(s <= a < e for a in rep for s, e in [r])}
        return len(hits), len(misses), len(gt_ranges) - len(gt_hit)

    tot = {'tp': 0, 'fp': 0, 'fn': 0, 'abstain': 0}
    for prog, opt, sid, sf, gt, mset, conf, ev, addr in rows:
        if ev == 'MISSED_SITE':
            tot['fn'] += len(gt)
            continue
        if conf is None:
            tot['abstain'] += 1
            tot['fn'] += len(gt)
        else:
            tp, fp, fn = site_scores(gt, mset)
            tot['tp'] += tp; tot['fp'] += fp; tot['fn'] += fn

    def f1(tp, fp, fn):
        p = tp / (tp + fp) if tp + fp else 0.0
        r = tp / (tp + fn) if tp + fn else 0.0
        f = 2 * p * r / (p + r) if p + r else 0.0
        return p, r, f

    p, r, f = f1(tot['tp'], tot['fp'], tot['fn'])
    print(f"VERDICT-v0.1: P={p:.3f} R={r:.3f} F1={f:.3f} "
          f"tp={tot['tp']} fp={tot['fp']} fn={tot['fn']} abstain={tot['abstain']} n={len(rows)}")
    print(f"Ghidra:    P=1.000 R=0.444 F1=0.615 tp=32 fp=0 fn=40")
    # per-site detail for misses
    print("\n=== VERDICT misses ===")
    for prog, opt, sid, sf, gt, mset, conf, ev, addr in rows:
        if ev == 'MISSED_SITE':
            print(f"{prog} {opt} {sid}: SITE NOT FOUND")
        elif conf is None:
            print(f"{prog} {opt} {sid} ({ev}): UNKNOWN, gt={len(gt)} targets")
        else:
            tp, fp, fn = site_scores(gt, mset)
            if fn > 0 or fp > 0:
                print(f"{prog} {opt} {sid} ({ev} conf={conf}): tp={tp} fp={fp} fn={fn}")

if __name__ == '__main__':
    main()
