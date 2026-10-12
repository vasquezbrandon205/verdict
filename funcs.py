#!/usr/bin/env python3
"""VERDICT-v0.1 function discovery: independent of Ghidra.
Strategies: ELF entry, direct-call targets, endbr64 markers, prologue patterns.
"""
from capstone.x86 import X86_OP_MEM, X86_REG_RIP
from foundation import CFG


class FunctionDiscovery:
    def __init__(self, cfg, loader):
        self.cfg = cfg
        self.loader = loader
        self.entries = set()

    def discover(self):
        # 1. ELF entry
        self.entries.add(self.loader.entry)
        # 2. Direct call targets
        for _, tgt in self.cfg.direct_calls:
            if tgt in self.cfg.insns:
                self.entries.add(tgt)
        # 3. endbr64 markers anywhere (CET function entry marker)
        for addr, insn in self.cfg.insns.items():
            if insn.mnemonic == 'endbr64':
                self.entries.add(addr)
        # 4. Address-taken: lea reg, [rip+X] where target is in .text
        tsec = self.loader.by_name['.text']
        tstart, tend = tsec['addr'], tsec['addr'] + tsec['size']
        for addr, insn in self.cfg.insns.items():
            if insn.mnemonic == 'lea' and len(insn.operands) == 2:
                op = insn.operands[1]
                if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                    tgt = addr + insn.size + op.mem.disp
                    if tstart <= tgt < tend:
                        self.entries.add(tgt)
        # 5. Classic prologues at block starts
        for bstart, bb in self.cfg.blocks.items():
            if not bb.insns:
                continue
            i0 = bb.insns[0]
            if i0.mnemonic == 'push' and i0.op_str in ('rbp', 'rbx', 'r12', 'r13', 'r14', 'r15'):
                self.entries.add(bstart)
        return sorted(self.entries)

    def functions(self):
        """Returns {entry: [block starts]} via CFG reachability."""
        entries = self.discover()
        func_blocks = {}
        for e in entries:
            # BFS from entry following succs, stopping at other entries
            seen, queue = set(), [e]
            while queue:
                b = queue.pop(0)
                if b in seen or b not in self.cfg.blocks:
                    continue
                if b != e and b in self.entries:
                    continue  # don't cross into another function
                seen.add(b)
                queue.extend(self.cfg.blocks[b].succs)
            func_blocks[e] = seen
        return func_blocks
