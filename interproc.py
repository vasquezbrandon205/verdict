#!/usr/bin/env python3
"""VERDICT-v0.2 interprocedural analysis v2.
Infers FP parameters from caller behavior, then resolves.
"""
from capstone.x86 import X86_OP_REG, X86_OP_IMM, X86_OP_MEM


class InterproceduralAnalyzer:
    def __init__(self, cfg, func_entries, dataflow):
        self.cfg = cfg
        self.func_entries = sorted(func_entries)
        self.df = dataflow
        self.callers = {}
        self._find_callers()

    def _find_callers(self):
        for addr, insn in self.cfg.insns.items():
            if insn.mnemonic not in ('call', 'callq'):
                continue
            if len(insn.operands) != 1:
                continue
            op = insn.operands[0]
            if op.type != X86_OP_IMM:
                continue
            callee = op.imm
            if callee in self.func_entries:
                caller = self.df.func_of(addr)
                if caller is not None:
                    self.callers.setdefault(callee, []).append((addr, insn, caller))

    def _get_param_reg(self, index):
        regs = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']
        return regs[index] if index < len(regs) else None

    def infer_fp_params(self, func_entry):
        """Infer which parameters are function pointers by examining callers.
        Returns set of param indices.
        """
        fp_params = set()
        for call_addr, call_insn, caller in self.callers.get(func_entry, []):
            for idx in range(6):
                preg = self._get_param_reg(idx)
                if not preg:
                    continue
                # Resolve what's passed as this arg
                targets = self.df._resolve_reg(caller, preg, call_addr)
                # If it resolves to function addresses, it's likely a FP param
                func_targets = {t for t in targets if t in self.df.func_entries}
                if func_targets:
                    fp_params.add(idx)
        return fp_params

    def resolve_site_interproc(self, site_addr):
        """Try interprocedural resolution.
        1. Infer FP params of the containing function from callers.
        2. For each FP param, resolve via callers and union.
        3. Return if non-empty.
        """
        func = self.df.func_of(site_addr)
        if func is None:
            return set(), None
        # Infer FP params
        fp_params = self.infer_fp_params(func)
        if not fp_params:
            return set(), None
        # For each FP param, resolve via callers
        all_targets = set()
        for idx in fp_params:
            preg = self._get_param_reg(idx)
            for call_addr, call_insn, caller in self.callers.get(func, []):
                targets = self.df._resolve_reg(caller, preg, call_addr)
                func_targets = {t for t in targets if t in self.df.func_entries}
                all_targets.update(func_targets)
        if all_targets:
            return all_targets, list(fp_params)[0]
        return set(), None
