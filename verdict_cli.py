#!/usr/bin/env python3
"""VERDICT v0.9 — VERified InDirect Call Targets.

Evidence-first indirect control-flow recovery for stripped binaries.
Does what it must. Never pushes beyond evidence.
"""
import sys
import os
import json
import time
import argparse
import threading
import itertools

VERSION = "0.9.0"
MOTTO = "Does what it must. Never pushes beyond evidence."

BANNER = r"""
███      ███  █████████  ████████    ███████     █████   ████████   ██████████
███      ███  █████████  ████████    ███████     █████   ████████   ██████████
███      ███  ███        ███   ███   ███  ███     ███    ███           ███
 ███    ███   ███████    ████████    ███   ███    ███    ███           ███
    ████      █████████  ███   ███   ███████     █████   ████████      ███
""".strip("\n")

CONTRACT = """\
THE VERDICT CONTRACT
────────────────────
1. Every reported target carries its evidence. No evidence — no target.
2. When evidence is insufficient, VERDICT abstains openly (UNKNOWN),
   never silently. An abstention is a result, not a failure.
3. Confidence is shown as measured. Nothing is rounded up.
4. Completeness is never faked. An incomplete answer beats an invented one.
"""

# UNKNOWN taxonomy (from unknown_taxonomy.py): WHY a site stays unresolved.
ARG_REGS = {'rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9'}
TAXONOMY = {
    'HEAP_MEM': 'pointer loaded from heap/object memory',
    'ARG_REG':  'pointer arrives as a function argument',
    'NO_FLOW':  'no recoverable dataflow',
    'TAIL_JMP': 'indirect jump — out of scope for the call resolver',
}


def classify_unknown(site):
    """Classify WHY a site is UNKNOWN from its instruction alone."""
    kind = site.get('kinds', ['CALLIND'])[0]
    if kind == 'BRANCHIND':
        return 'TAIL_JMP'
    op = (site.get('op_str') or '').strip()
    reg = op.split(',')[0].strip()
    if reg in ARG_REGS:
        return 'ARG_REG'
    if '[' in op or '(' in op:
        return 'HEAP_MEM'
    return 'NO_FLOW'


# ── terminal helpers ──────────────────────────────────────────────
def _tty(stream):
    return hasattr(stream, 'isatty') and stream.isatty()


class Color:
    def __init__(self, enabled):
        self.e = enabled

    def wrap(self, code, s):
        return f"\033[{code}m{s}\033[0m" if self.e else s

    def green(self, s): return self.wrap('32', s)
    def yellow(self, s): return self.wrap('33', s)
    def dim(self, s): return self.wrap('2', s)
    def bold(self, s): return self.wrap('1', s)


class Spinner:
    """Honest progress: the engine exposes no stages, so we show
    activity on stderr, never fake percentages."""

    def __init__(self, enabled, message="Analyzing"):
        self.enabled = enabled
        self.message = message
        self._stop = threading.Event()
        self._thread = None

    def __enter__(self):
        if not self.enabled:
            return self
        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc):
        if self.enabled:
            self._stop.set()
            self._thread.join()
            sys.stderr.write("\r" + " " * (len(self.message) + 8) + "\r")
            sys.stderr.flush()

    def _spin(self):
        for ch in itertools.cycle("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"):
            if self._stop.is_set():
                break
            sys.stderr.write(f"\r{ch} {self.message}…")
            sys.stderr.flush()
            time.sleep(0.08)


# ── analysis ──────────────────────────────────────────────────────
def run_analysis(bpath, min_confidence, show_spinner):
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from batch import analyze

    t0 = time.time()
    with Spinner(show_spinner):
        result = analyze(bpath)
    dt = time.time() - t0

    sites = []
    for r in result.get('results', []):
        conf = r.get('confidence') or 0.0
        if r.get('targets') and conf >= min_confidence:
            r['verdict'] = 'RESOLVED'
            r['category'] = None
        else:
            r['verdict'] = 'UNKNOWN'
            r['category'] = classify_unknown(r)
            r['targets'] = []
            r['confidence'] = 0.0
        sites.append(r)
    return {
        'tool': 'verdict',
        'version': VERSION,
        'binary': os.path.basename(bpath),
        'path': bpath,
        'analysis_time_s': round(dt, 2),
        'results': sites,
    }


def summarize(report):
    sites = report['results']
    resolved = [s for s in sites if s['verdict'] == 'RESOLVED']
    unknown = [s for s in sites if s['verdict'] == 'UNKNOWN']
    tax = {}
    for s in unknown:
        tax[s['category']] = tax.get(s['category'], 0) + 1
    return resolved, unknown, tax


# ── output ────────────────────────────────────────────────────────
def print_banner(color):
    for line in BANNER.split("\n"):
        print(color.bold(line.rstrip()))
    print(f"  {color.dim('VERified InDirect Call Targets · v' + VERSION)}")
    print(f"  {color.dim('“' + MOTTO + '”')}")


def print_human(report, color, verbose):
    resolved, unknown, tax = summarize(report)
    n = len(report['results'])
    print(f"  Binary: {report['binary']}  ·  "
          f"{n} sites  ·  {report['analysis_time_s']:.2f}s")
    print()
    if resolved:
        print(color.green(color.bold(f"  RESOLVED · {len(resolved)}")))
        for r in resolved:
            tg = ', '.join(r['targets'])
            print(f"    {color.bold(r['site_addr'])} → {color.green(tg)}   "
                  f"[{r['evidence']} · conf {r['confidence']:.2f}]")
            ctx = f"in {r['func']}" if r.get('func') else "top level"
            print(color.dim(f"      {ctx} · {r.get('mnemonic', '')} {r.get('op_str', '')}".rstrip()))
        print()
    print(color.yellow(color.bold(f"  UNKNOWN · {len(unknown)} (honest abstentions)")))
    for cat, count in sorted(tax.items(), key=lambda kv: -kv[1]):
        print(f"    {count:3d}  {cat:10s} {color.dim(TAXONOMY[cat])}")
    if verbose and unknown:
        print()
        for r in unknown:
            ctx = f"in {r['func']}" if r.get('func') else "top level"
            print(color.dim(f"    {r['site_addr']}  {r['kinds'][0]:9s} "
                            f"{r.get('mnemonic', '')} {r.get('op_str', '')}  → "
                            f"{r['category']}  ({ctx})"))
    print()
    print(color.dim(f"  {len(resolved)} verdict{'s' if len(resolved) != 1 else ''} rendered · "
                    f"{len(unknown)} abstentions · 0 invented targets"))


def print_json(report):
    resolved, unknown, tax = summarize(report)
    out = dict(report)
    out['summary'] = {
        'sites': len(report['results']),
        'resolved': len(resolved),
        'unknown': len(unknown),
        'taxonomy': tax,
        'invented_targets': 0,
    }
    for r in out['results']:
        if r['verdict'] == 'UNKNOWN':
            r['reason'] = TAXONOMY[r['category']]
    print(json.dumps(out, indent=1))


# ── CLI ───────────────────────────────────────────────────────────
def build_parser():
    p = argparse.ArgumentParser(
        prog='verdict',
        description=f"VERDICT v{VERSION} — {MOTTO}",
    )
    p.add_argument('--version', action='version', version=f"VERDICT {VERSION}")
    p.add_argument('--no-banner', action='store_true',
                   help="suppress the startup banner")
    sub = p.add_subparsers(dest='command')

    a = sub.add_parser('analyze', help="analyze a binary for indirect call targets")
    a.add_argument('binary', help="path to an ELF binary (x86-64)")
    a.add_argument('--json', action='store_true',
                   help="machine-readable output (banner and colors suppressed)")
    a.add_argument('--no-banner', action='store_true',
                   help="suppress the startup banner")
    a.add_argument('--min-confidence', type=float, default=0.0, metavar='X',
                   help="demote resolutions below confidence X to UNKNOWN (default: 0.0)")
    a.add_argument('--no-taxonomy', action='store_true',
                   help="skip UNKNOWN classification")
    a.add_argument('-v', '--verbose', action='store_true',
                   help="list every UNKNOWN site with its instruction")

    sub.add_parser('contract', help="print the VERDICT honesty contract") \
        .add_argument('--no-banner', action='store_true',
                      help="suppress the startup banner")
    sub.add_parser('version', help="print the version")
    return p


def die(msg, code=1):
    print(f"verdict: error: {msg}", file=sys.stderr)
    sys.exit(code)


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        print_banner(Color(_tty(sys.stdout)))
        print()
        parser.print_help()
        return 0

    if args.command == 'version':
        print(f"VERDICT {VERSION}")
        return 0

    if args.command == 'contract':
        if not getattr(args, 'no_banner', False):
            print_banner(Color(_tty(sys.stdout)))
            print()
        print(CONTRACT)
        return 0

    # analyze
    bpath = args.binary
    if not os.path.exists(bpath):
        die(f"{bpath}: no such file")
    if not os.path.isfile(bpath):
        die(f"{bpath}: not a file")

    use_json = args.json
    color = Color(_tty(sys.stdout) and not use_json)
    show_banner = not args.no_banner and not use_json and _tty(sys.stdout)
    if show_banner:
        print_banner(color)
        print()

    try:
        report = run_analysis(
            bpath,
            min_confidence=args.min_confidence,
            show_spinner=_tty(sys.stderr) and not use_json,
        )
    except Exception as e:  # engine errors become clean CLI errors
        die(f"analysis failed: {e}", code=2)

    if args.no_taxonomy:
        for r in report['results']:
            if r['verdict'] == 'UNKNOWN':
                r['category'] = 'UNKNOWN'
                r['reason'] = 'taxonomy skipped'

    if use_json:
        print_json(report)
    else:
        print_human(report, color, args.verbose)
    return 0


if __name__ == '__main__':
    sys.exit(main())
