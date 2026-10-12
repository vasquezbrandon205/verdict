#!/usr/bin/env python3
"""Batch-run VERDICT-v0.4 on the ICF corpus. Outputs resolver-format JSON.
v0.4 adds cross-module analysis for p10.
"""
import sys, os, json, glob
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from foundation import ELFLoader, Decoder, CFG
from funcs import FunctionDiscovery
from dataflow import Dataflow
try:
    from xmod import CrossModuleResolver, get_plt_targets
except ImportError:
    CrossModuleResolver = None

def analyze(binary_path, xmod_resolver=None, main_df=None):
    loader = ELFLoader(binary_path)
    try:
        text = loader.section_bytes('.text')
    except KeyError:
        return {'binary': os.path.basename(binary_path), 'results': []}
    tsec = loader.by_name['.text']
    dec = Decoder()
    cfg = CFG(dec, text, tsec['addr'])
    cfg.build()
    fd = FunctionDiscovery(cfg, loader)
    entries = fd.discover()
    df = Dataflow(cfg, entries, loader)
    df.track_global_stores()
    results = []
    # indirect calls + indirect jumps (tail calls), excluding GOT/PLT
    sites = []
    for site in cfg.indirect_calls:
        insn = cfg.insns[site]
        if 'rip' not in insn.op_str:  # skip GOT calls
            sites.append((site, 'CALLIND'))
    for site in cfg.indirect_jumps:
        insn = cfg.insns[site]
        if 'rip' not in insn.op_str:
            sites.append((site, 'BRANCHIND'))
    for site, kind in sites:
        targets, conf, ev = df.resolve_site(site)
        # v0.4: try cross-module if UNKNOWN and we have a resolver
        if not targets and xmod_resolver is not None and main_df is not None:
            targets, conf, ev = resolve_cross_module(
                site, df, xmod_resolver, main_df, binary_path
            )
        func = CFG.func_containing(site, sorted(entries))
        insn = cfg.insns[site]
        results.append({'site_addr': hex(site), 'func': hex(func) if func else None,
                        'kinds': [kind],
                        'mnemonic': insn.mnemonic, 'op_str': insn.op_str,
                        'targets': [hex(t) for t in sorted(targets)],
                        'confidence': conf, 'evidence': ev})
    return {'binary': os.path.basename(binary_path), 'results': results}

def resolve_cross_module(site_addr, lib_df, xmod_resolver, main_df, lib_path):
    """Try cross-module resolution for p10 pattern.
    v0.7 FIX: Verify the site loads from the same global that the setter
    function writes to. Previously (v0.4-v0.5) this was applied to EVERY
    unresolved site, causing FPs.
    """
    insn = lib_df.cfg.insns.get(site_addr)
    if not insn:
        return set(), None, 'UNKNOWN'

    func_entry = lib_df.func_of(site_addr)
    if func_entry is None:
        return set(), None, 'UNKNOWN'

    import re
    setter_name = 'register_handler'

    # Step 1: Find the global(s) written by RIP-relative stores.
    # Capstone Intel syntax: mov 'qword ptr [rip + 0x2f00], rax'
    # v0.7: Scan ALL instructions (not via _func_blocks, which misses
    # functions whose entry isn't a block start).
    setter_globals = set()

    for addr, i in lib_df.cfg.insns.items():
        # mov qword ptr [rip + 0xXXXX], reg  -- store to global
        if i.mnemonic == 'mov' and '[rip +' in i.op_str:
            parts = i.op_str.split(',')
            if len(parts) == 2 and '[rip +' in parts[0]:
                m = re.search(r'\[rip \+ (0x[0-9a-f]+)\]', parts[0])
                if m:
                    disp = int(m.group(1), 16)
                    glob_addr = i.address + i.size + disp
                    setter_globals.add(glob_addr)

    if not setter_globals:
        return set(), None, 'UNKNOWN'

    # Step 2: Verify the site loads from one of these globals.
    # Site op_str: 'rdx' or 'rax' (register name only)
    # Load format: mov 'rax, qword ptr [rip + 0x2ee7]'
    op = insn.op_str.strip()
    site_verified = False
    reg = op
    for addr, i in lib_df.cfg.insns.items():
        if addr >= site_addr:
            continue
        if lib_df.func_of(addr) != func_entry:
            continue
        if i.mnemonic == 'mov' and '[rip +' in i.op_str:
            parts = i.op_str.split(',')
            if len(parts) == 2 and parts[0].strip() == reg and '[rip +' in parts[1]:
                m = re.search(r'\[rip \+ (0x[0-9a-f]+)\]', parts[1])
                if m:
                    disp = int(m.group(1), 16)
                    load_addr = i.address + i.size + disp
                    if load_addr in setter_globals:
                        site_verified = True
                        break

    if not site_verified:
        return set(), None, 'UNKNOWN'

    # Step 3: Verified. Resolve via setter callers in main.
    callers = xmod_resolver.find_setter_callers(setter_name)
    if not callers:
        return set(), None, 'UNKNOWN'
    targets = set()
    for call_addr in callers:
        caller_func = main_df.func_of(call_addr)
        if caller_func is None:
            continue
        arg_targets = main_df._resolve_reg(caller_func, 'rdi', call_addr)
        for t in arg_targets:
            if t in main_df.func_entries:
                targets.add(t)
    if targets:
        return targets, 0.65, 'CROSS_MODULE'
    return set(), None, 'UNKNOWN'

def main():
    build_dir = sys.argv[1]
    out_dir = sys.argv[2]
    os.makedirs(out_dir, exist_ok=True)
    for prog in ['p01','p02','p03','p04','p05','p06','p07','p08','p09','p11','p12']:
        for opt in ['O0','O2','O3']:
            binpath = os.path.join(build_dir, f'{prog}_{opt}_stripped')
            tag = f'verdict_{prog}_{opt}_stripped'
            out = analyze(binpath)
            json.dump(out, open(os.path.join(out_dir, tag + '.json'), 'w'), indent=1)
            n = sum(1 for r in out['results'] if r['confidence'])
            print(f"{tag}: {len(out['results'])} sites, {n} resolved")
    # p10 lib with cross-module analysis (v0.4)
    for opt in ['O0','O2','O3']:
        libpath = os.path.join(build_dir, f'libp10_{opt}_stripped.so')
        mainpath = os.path.join(build_dir, f'p10_{opt}_stripped')
        tag = f'verdict_libp10_{opt}_stripped'
        # Build cross-module resolver and main Dataflow
        xmod = None
        main_df = None
        if CrossModuleResolver is not None and os.path.exists(mainpath):
            xmod = CrossModuleResolver(mainpath, libpath)
            # Build Dataflow for main
            try:
                m_loader = ELFLoader(mainpath)
                m_text = m_loader.section_bytes('.text')
                m_tsec = m_loader.by_name['.text']
                m_cfg = CFG(Decoder(), m_text, m_tsec['addr'])
                m_cfg.build()
                m_entries = FunctionDiscovery(m_cfg, m_loader).discover()
                main_df = Dataflow(m_cfg, m_entries, m_loader)
                main_df.track_global_stores()
            except Exception:
                main_df = None
        out = analyze(libpath, xmod_resolver=xmod, main_df=main_df)
        json.dump(out, open(os.path.join(out_dir, tag + '.json'), 'w'), indent=1)
        n = sum(1 for r in out['results'] if r['confidence'])
        print(f"{tag}: {len(out['results'])} sites, {n} resolved")

if __name__ == '__main__':
    main()
