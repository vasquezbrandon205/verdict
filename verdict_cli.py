#!/usr/bin/env python3
"""VERDICT-v0.9 CLI. Single-binary analysis with human-readable output."""
import sys, os, json, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from batch import analyze

def main():
    if len(sys.argv) < 2:
        print("Usage: verdict_cli.py <binary> [--json]")
        print("  Analyze a binary for indirect call targets.")
        sys.exit(1)
    bpath = sys.argv[1]
    as_json = '--json' in sys.argv
    if not os.path.exists(bpath):
        print(f"Error: {bpath} not found", file=sys.stderr)
        sys.exit(1)

    t0 = time.time()
    result = analyze(bpath)
    dt = time.time() - t0

    if as_json:
        result['analysis_time_s'] = round(dt, 2)
        print(json.dumps(result, indent=1))
        return

    # Human-readable
    print(f"VERDICT v0.9 analysis: {os.path.basename(bpath)}")
    print(f"  Time: {dt:.2f}s")
    resolved = [r for r in result['results'] if r['confidence']]
    unknown = [r for r in result['results'] if not r['confidence']]
    print(f"  Sites: {len(result['results'])} total, {len(resolved)} resolved, {len(unknown)} unknown")
    print()
    if resolved:
        print("Resolved indirect calls:")
        for r in resolved:
            targets = ', '.join(r['targets'])
            print(f"  {r['site_addr']}: -> {targets}")
            print(f"    evidence={r['evidence']} confidence={r['confidence']}")
    if unknown:
        print(f"\n{len(unknown)} sites returned UNKNOWN (honest abstention, not a miss)")

if __name__ == '__main__':
    main()
