#!/usr/bin/env python3
"""VERDICT-v0.2 dataflow: kill-aware + vtable support.
- Intra-block kill analysis for precision (P=1.0).
- Vtable analysis for C++ virtual dispatch.
- Returns UNKNOWN when uncertain (preserve precision).
"""
import struct
from capstone.x86 import X86_OP_REG, X86_OP_IMM, X86_OP_MEM, X86_REG_RIP
from foundation import CFG
try:
    from vtable import VtableAnalyzer
except ImportError:
    VtableAnalyzer = None
try:
    from interproc import InterproceduralAnalyzer
except ImportError:
    InterproceduralAnalyzer = None
try:
    from simd import SimdAnalyzer
except ImportError:
    SimdAnalyzer = None


class Dataflow:
    def __init__(self, cfg, func_entries, loader=None):
        self.cfg = cfg
        self.func_entries = sorted(func_entries)
        self.loader = loader
        self.globals = {}
        if loader:
            self._find_globals()
        # vtable analyzer (lazy)
        self._vtable_analyzer = None
        # interprocedural analyzer (lazy)
        self._interproc_analyzer = None
        # SIMD analyzer (lazy)
        self._simd_analyzer = None

    def _get_vtable_analyzer(self):
        if self._vtable_analyzer is None and VtableAnalyzer is not None:
            self._vtable_analyzer = VtableAnalyzer(self.cfg, self.func_entries, self.loader)
        return self._vtable_analyzer

    def _get_interproc_analyzer(self):
        if self._interproc_analyzer is None and InterproceduralAnalyzer is not None:
            self._interproc_analyzer = InterproceduralAnalyzer(self.cfg, self.func_entries, self)
        return self._interproc_analyzer

    def _get_simd_analyzer(self):
        if self._simd_analyzer is None and SimdAnalyzer is not None:
            self._simd_analyzer = SimdAnalyzer(self.cfg, self.func_entries, self)
        return self._simd_analyzer

    def _reg_norm(self, name):
        norm = {'eax': 'rax', 'ax': 'rax', 'ah': 'rax', 'al': 'rax',
                'ebx': 'rbx', 'bx': 'rbx', 'bh': 'rbx', 'bl': 'rbx',
                'ecx': 'rcx', 'cx': 'rcx', 'ch': 'rcx', 'cl': 'rcx',
                'edx': 'rdx', 'dx': 'rdx', 'dh': 'rdx', 'dl': 'rdx',
                'esi': 'rsi', 'si': 'rsi', 'sil': 'rsi',
                'edi': 'rdi', 'di': 'rdi', 'dil': 'rdi',
                'ebp': 'rbp', 'bp': 'rbp', 'bpl': 'rbp',
                'esp': 'rsp', 'sp': 'rsp', 'spl': 'rsp'}
        return norm.get(name, name)

    def func_of(self, addr):
        return CFG.func_containing(addr, self.func_entries)

    def _find_globals(self):
        tsec = self.loader.by_name['.text']
        tstart, tend = tsec['addr'], tsec['addr'] + tsec['size']
        for secname in ('.data', '.rodata', '.data.rel.ro', '.data.rel.ro.local'):
            if secname not in self.loader.by_name:
                continue
            sec = self.loader.by_name[secname]
            if sec['type'] == 8:
                continue
            data = self.loader.section_bytes(secname)
            for i in range(0, len(data) - 7, 8):
                (val,) = struct.unpack_from('<Q', data, i)
                if tstart <= val < tend and val in self.func_entries:
                    gaddr = sec['addr'] + i
                    self.globals.setdefault(gaddr, set()).add(val)

    def _writes_reg(self, insn, reg_name):
        if not insn.operands:
            return False
        if insn.mnemonic in ('cmp', 'test', 'jmp', 'je', 'jne', 'ja', 'jb',
                             'call', 'ret', 'nop', 'hlt', 'leave', 'push'):
            return False
        op0 = insn.operands[0]
        if op0.type == X86_OP_REG:
            rname = self._reg_norm(insn.reg_name(op0.reg))
            return rname == self._reg_norm(reg_name)
        return False

    def _func_blocks(self, func_entry):
        seen, queue, blocks = set(), [func_entry], []
        while queue:
            b = queue.pop(0)
            if b in seen or b not in self.cfg.blocks:
                continue
            if b != func_entry and b in self.func_entries:
                continue
            seen.add(b)
            blocks.append(b)
            queue.extend(self.cfg.blocks[b].succs)
        return blocks

    def _find_block(self, addr):
        """Find block containing addr."""
        for bstart, bb in self.cfg.blocks.items():
            for ins in bb.insns:
                if ins.address == addr:
                    return bstart, bb
        return None, None

    def _resolve_reg(self, func_entry, reg_name, before_addr, depth=0):
        """Resolve register to set of function addresses. v0.2: kill-aware.
        1. Find nearest def in same block (intra-block kill).
        2. If it's a constant/load -> return (kills).
        3. If it's cmove -> include and continue to predecessors.
        4. If no def in block -> go to predecessors."""
        if depth > 3:
            return set()
        reg_norm = self._reg_norm(reg_name)
        # Find block containing before_addr
        site_block_start, site_bb = self._find_block(before_addr)
        if site_bb is None:
            return set()
        # Walk backward in the block to find nearest def
        nearest = None
        for insn in reversed(site_bb.insns):
            if insn.address >= before_addr:
                continue
            if self._writes_reg(insn, reg_norm):
                nearest = insn
                break
        targets = set()
        if nearest is not None:
            t = self._resolve_def(nearest, func_entry, before_addr, depth)
            # Check if it's a kill
            m = nearest.mnemonic
            is_kill = False
            if m in ('mov', 'movabs') and len(nearest.operands) == 2:
                src = nearest.operands[1]
                if src.type == X86_OP_MEM:
                    is_kill = True  # load kills
                elif src.type == X86_OP_IMM:
                    is_kill = True  # constant kills
            elif m == 'lea':
                is_kill = True  # lea kills
            # cmove does NOT kill (conditional)
            if is_kill:
                return t
            targets.update(t)
            # For cmove (and other non-kills), continue to earlier defs
            # including those in the same block before the nearest
            nearest_addr = nearest.address if nearest else before_addr
        else:
            nearest_addr = before_addr
        # Search for earlier defs: in same block before nearest, plus other blocks
        defs = []
        for b in self._func_blocks(func_entry):
            bb = self.cfg.blocks[b]
            for insn in bb.insns:
                if insn.address >= nearest_addr:
                    continue
                if insn.address >= before_addr:
                    continue
                if not self._writes_reg(insn, reg_norm):
                    continue
                # Skip the nearest itself (already processed)
                if nearest is not None and insn.address == nearest.address:
                    continue
                defs.append(insn)
        defs.sort(key=lambda i: i.address, reverse=True)
        for insn in defs:
            t = self._resolve_def(insn, func_entry, before_addr, depth)
            if t:
                # Memory load: kill (but we're already in predecessor search,
                # so this is for completeness)
                if insn.mnemonic in ('mov', 'movabs') and len(insn.operands) == 2:
                    src = insn.operands[1]
                    if src.type == X86_OP_MEM:
                        targets.update(t)
                        # Don't return; there might be branches
                        continue
                targets.update(t)
        return targets

    def _resolve_def(self, insn, func_entry, before_addr, depth):
        """Resolve a single definition instruction to function addresses."""
        m = insn.mnemonic
        targets = set()
        if m == 'lea' and len(insn.operands) == 2:
            src = insn.operands[1]
            if src.type == X86_OP_MEM:
                try:
                    bn = insn.reg_name(src.mem.base)
                except:
                    bn = ''
                if bn == 'rip':
                    tgt = insn.address + insn.size + src.mem.disp
                    if tgt in self.func_entries:
                        targets.add(tgt)
        elif m in ('mov', 'movabs') and len(insn.operands) == 2:
            src = insn.operands[1]
            if src.type == X86_OP_IMM and src.imm in self.func_entries:
                targets.add(src.imm)
            elif src.type == X86_OP_REG:
                sr = insn.reg_name(src.reg)
                targets.update(self._resolve_reg(func_entry, sr, insn.address, depth + 1))
            elif src.type == X86_OP_MEM:
                t = self._resolve_mem(insn, src, func_entry, before_addr, depth)
                targets.update(t)
        elif m in ('cmove', 'cmovne', 'cmova', 'cmovb', 'cmovg', 'cmovl'):
            if len(insn.operands) == 2:
                src = insn.operands[1]
                if src.type == X86_OP_REG:
                    sr = insn.reg_name(src.reg)
                    targets.update(self._resolve_reg(func_entry, sr, insn.address, depth + 1))
        return targets

    def _resolve_mem(self, insn, op, func_entry, before_addr, depth):
        """Resolve memory operand to function addresses (global, stack slot, or SIB table)."""
        if op.mem.base == 0:
            return set()
        try:
            bn = insn.reg_name(op.mem.base)
        except:
            return set()
        if bn == 'rip':
            gaddr = insn.address + insn.size + op.mem.disp
            return set(self.globals.get(gaddr, set()))
        # v0.3: SIB table lookup: [base + index*8 + disp]
        # This is a table of function pointers. Collect all entries.
        if op.mem.index != 0 and op.mem.scale == 8:
            return self._resolve_sib_table(insn, op, func_entry, before_addr, depth)
        # stack slot: find stores to this slot
        slot = None
        if bn in ('rbp', 'ebp'):
            slot = ('rbp', op.mem.disp)
        elif bn in ('rsp', 'esp'):
            slot = ('rsp', op.mem.disp)
        if slot is None:
            return set()
        # find stores to this slot (flow-insensitive, but only in same function)
        targets = set()
        for b in self._func_blocks(func_entry):
            bb = self.cfg.blocks[b]
            for sin in bb.insns:
                if sin.address >= before_addr:
                    continue
                if sin.mnemonic in ('mov', 'movabs') and len(sin.operands) == 2:
                    dst, src = sin.operands[0], sin.operands[1]
                    if dst.type != X86_OP_MEM:
                        continue
                    try:
                        dbn = sin.reg_name(dst.mem.base)
                    except:
                        continue
                    dslot = None
                    if dbn in ('rbp', 'ebp') and dst.mem.disp == slot[1] and slot[0] == 'rbp':
                        dslot = slot
                    elif dbn in ('rsp', 'esp') and dst.mem.disp == slot[1] and slot[0] == 'rsp':
                        dslot = slot
                    if dslot is None:
                        continue
                    # resolve src
                    if src.type == X86_OP_IMM and src.imm in self.func_entries:
                        targets.add(src.imm)
                    elif src.type == X86_OP_REG:
                        sr = sin.reg_name(src.reg)
                        targets.update(self._resolve_reg(func_entry, sr, sin.address, depth + 1))
        return targets

    def _resolve_sib_table(self, insn, op, func_entry, before_addr, depth):
        """Resolve SIB table lookup: [base + index*8 + disp].
        Collects all function addresses stored in the table region.
        The table base is at (base_reg + disp). Entries are 8 bytes.
        We collect stores to nearby slots (within 64 bytes) as the table.
        """
        try:
            base_name = insn.reg_name(op.mem.base)
        except:
            return set()
        base_disp = op.mem.disp
        # Determine base key
        if base_name in ('rbp', 'ebp'):
            base_key = 'rbp'
        elif base_name in ('rsp', 'esp'):
            base_key = 'rsp'
        else:
            return set()
        # Collect stores to slots near base_disp
        # Table entries are 8 bytes; look for stores within a reasonable range
        # For p02: table at [rbp-0x30] with 4 entries -> disps -0x30, -0x28, -0x20, -0x18
        targets = set()
        for b in self._func_blocks(func_entry):
            bb = self.cfg.blocks[b]
            for sin in bb.insns:
                if sin.address >= before_addr:
                    continue
                if sin.mnemonic not in ('mov', 'movabs'):
                    continue
                if len(sin.operands) != 2:
                    continue
                dst, src = sin.operands[0], sin.operands[1]
                if dst.type != X86_OP_MEM:
                    continue
                # Check if dst is a stack slot with same base
                try:
                    dbn = sin.reg_name(dst.mem.base)
                except:
                    continue
                if dbn not in ('rbp', 'ebp', 'rsp', 'esp'):
                    continue
                # Normalize base
                dbn_norm = 'rbp' if dbn in ('rbp', 'ebp') else 'rsp'
                if dbn_norm != base_key:
                    continue
                # Check if disp is within table range
                # Table base is at base_disp; entries go upward (higher addresses)
                # For [rbp-0x30] with 4 entries: -0x30, -0x28, -0x20, -0x18
                # So disp should be >= base_disp and < base_disp + 64
                d = dst.mem.disp
                if d < base_disp or d >= base_disp + 64:
                    continue
                # Must be 8-byte aligned relative to base
                if (d - base_disp) % 8 != 0:
                    continue
                # Resolve the stored value
                if src.type == X86_OP_IMM and src.imm in self.func_entries:
                    targets.add(src.imm)
                elif src.type == X86_OP_REG:
                    try:
                        sr = sin.reg_name(src.reg)
                        t = self._resolve_reg(func_entry, sr, sin.address, depth + 1)
                        targets.update(t)
                    except:
                        pass
        # Filter to function entries
        return {t for t in targets if t in self.func_entries}

    def track_global_stores(self):
        """Update globals with dynamically stored function addresses."""
        data_ranges = []
        for secname in ('.data', '.bss', '.rodata', '.data.rel.ro'):
            if secname in self.loader.by_name:
                s = self.loader.by_name[secname]
                data_ranges.append((s['addr'], s['addr'] + s['size']))
        for addr, insn in self.cfg.insns.items():
            if insn.mnemonic not in ('mov', 'movabs') or len(insn.operands) != 2:
                continue
            dst, src = insn.operands[0], insn.operands[1]
            if dst.type != X86_OP_MEM:
                continue
            gaddr = None
            if dst.mem.base != 0:
                try:
                    bn = insn.reg_name(dst.mem.base)
                except:
                    continue
                if bn == 'rip':
                    gaddr = addr + insn.size + dst.mem.disp
            if gaddr is None:
                continue
            if not any(s <= gaddr < e for s, e in data_ranges):
                continue
            if src.type == X86_OP_REG:
                func = self.func_of(addr)
                if func is not None:
                    sr = insn.reg_name(src.reg)
                    t = self._resolve_reg(func, sr, addr)
                    if t:
                        self.globals.setdefault(gaddr, set()).update(t)

    def resolve_site(self, site_addr):
        """Returns (targets:set, confidence, evidence). v0.2: tries vtable."""
        insn = self.cfg.insns.get(site_addr)
        if not insn:
            return set(), None, 'NOT_FOUND'
        m = insn.mnemonic
        if 'call' not in m and 'jmp' not in m:
            return set(), None, 'NOT_INDIRECT'
        if len(insn.operands) != 1:
            return set(), None, 'UNKNOWN'
        op = insn.operands[0]
        if op.type == X86_OP_IMM:
            return {op.imm}, 0.95, 'DIRECT'
        if op.type == X86_OP_REG:
            func = self.func_of(site_addr)
            if func is None:
                return set(), None, 'UNKNOWN'
            reg = insn.reg_name(op.reg)
            targets = self._resolve_reg(func, reg, site_addr)
            # Filter to only function entries (remove non-code addresses)
            targets = {t for t in targets if t in self.func_entries}
            if targets:
                return targets, 0.85, 'DATAFLOW'
            # v0.2: try vtable resolution for virtual calls
            va = self._get_vtable_analyzer()
            if va is not None:
                vt_targets, slot = va.resolve_virtual_call(site_addr, func)
                vt_targets = {t for t in vt_targets if t in self.func_entries}
                if vt_targets:
                    return vt_targets, 0.75, f'VTABLE_SLOT{slot}'
            # v0.2: try interprocedural resolution for parameters
            ia = self._get_interproc_analyzer()
            if ia is not None:
                ip_targets, param_idx = ia.resolve_site_interproc(site_addr)
                ip_targets = {t for t in ip_targets if t in self.func_entries}
                if ip_targets:
                    return ip_targets, 0.70, f'INTERPROC_PARAM{param_idx}'
            return set(), None, 'UNKNOWN'
        # memory-indirect: try vtable, SIMD, then global/stack
        if op.type == X86_OP_MEM:
            func = self.func_of(site_addr)
            if func is None:
                return set(), None, 'UNKNOWN'
            # v0.3: try vtable for memory-indirect calls (call *N(%reg))
            va = self._get_vtable_analyzer()
            if va is not None:
                vt_targets, slot = va.resolve_virtual_call(site_addr, func)
                vt_targets = {t for t in vt_targets if t in self.func_entries}
                if vt_targets:
                    return vt_targets, 0.75, f'VTABLE_SLOT{slot}_MEM'
            # v0.3: try SIMD table for indexed calls (call *N(base,index,8))
            if op.mem.index != 0 and op.mem.scale == 8:
                sa = self._get_simd_analyzer()
                if sa is not None:
                    simd_targets = sa.resolve_simd_table_call(site_addr, func)
                    simd_targets = {t for t in simd_targets if t in self.func_entries}
                    if simd_targets:
                        return simd_targets, 0.70, 'SIMD_TABLE'
            targets = self._resolve_mem(insn, op, func, site_addr, 0)
            targets = {t for t in targets if t in self.func_entries}
            if targets:
                return targets, 0.80, 'DATAFLOW_MEM'
            return set(), None, 'UNKNOWN_MEM'
        return set(), None, 'UNKNOWN'
