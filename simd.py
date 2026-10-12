#!/usr/bin/env python3
"""VERDICT-v0.3 SIMD/packed dataflow for vectorized table construction.
Models XMM registers as pairs of 64-bit lanes, tracks function addresses
through movq/punpcklqdq/movaps.
"""
from capstone.x86 import X86_OP_REG, X86_OP_IMM, X86_OP_MEM


class SimdAnalyzer:
    def __init__(self, cfg, func_entries, dataflow):
        self.cfg = cfg
        self.func_entries = set(func_entries)
        self.df = dataflow

    def _xmm_name(self, insn, reg_id):
        """Get XMM register name."""
        try:
            name = insn.reg_name(reg_id)
            if name.startswith('xmm'):
                return name
        except:
            pass
        return None

    def analyze_function(self, func_entry, up_to_addr):
        """Analyze SIMD dataflow in function up to addr.
        Returns: (xmm_state, mem_tables)
        - xmm_state: dict xmm_name -> [lane0, lane1] (func addr or None)
        - mem_tables: dict mem_addr -> [func addrs] (from movaps stores)
        """
        xmm = {}  # xmm_name -> [lane0, lane1]
        mem_tables = {}  # addr -> list of funcs (16-byte aligned stores)
        
        # Get blocks in function
        blocks = self.df._func_blocks(func_entry)
        # Sort by address for forward analysis
        all_insns = []
        for b in blocks:
            bb = self.cfg.blocks[b]
            for ins in bb.insns:
                if ins.address < up_to_addr:
                    all_insns.append(ins)
        all_insns.sort(key=lambda i: i.address)
        
        for insn in all_insns:
            m = insn.mnemonic
            if m == 'movq' and len(insn.operands) == 2:
                dst, src = insn.operands[0], insn.operands[1]
                # movq r64 -> xmm: lane0 = resolve(r64)
                if dst.type == X86_OP_REG and src.type == X86_OP_REG:
                    xmm_dst = self._xmm_name(insn, dst.reg)
                    if xmm_dst:
                        try:
                            src_name = insn.reg_name(src.reg)
                            targets = self.df._resolve_reg(func_entry, src_name, insn.address)
                            func_targets = [t for t in targets if t in self.func_entries]
                            # Take first (should be single for lea)
                            val = func_targets[0] if func_targets else None
                            xmm[xmm_dst] = [val, None]
                        except:
                            pass
                # movq xmm -> r64: r64 = lane0 (handled by dataflow, skip)
            elif m == 'punpcklqdq' and len(insn.operands) == 2:
                dst, src = insn.operands[0], insn.operands[1]
                # punpcklqdq src, dst: dst = [dst[0], src[0]]
                if dst.type == X86_OP_REG and src.type == X86_OP_REG:
                    dst_name = self._xmm_name(insn, dst.reg)
                    src_name = self._xmm_name(insn, src.reg)
                    if dst_name and src_name:
                        dst_lanes = xmm.get(dst_name, [None, None])
                        src_lanes = xmm.get(src_name, [None, None])
                        xmm[dst_name] = [dst_lanes[0], src_lanes[0]]
            elif m in ('movaps', 'movapd', 'movdqa') and len(insn.operands) == 2:
                dst, src = insn.operands[0], insn.operands[1]
                # movaps xmm -> mem: store 16 bytes (2 lanes)
                if dst.type == X86_OP_MEM and src.type == X86_OP_REG:
                    src_name = self._xmm_name(insn, src.reg)
                    if src_name and src_name in xmm:
                        lanes = xmm[src_name]
                        # Compute target address
                        addr = self._resolve_mem_addr(insn, dst, func_entry)
                        if addr is not None:
                            # Store both lanes (filter None)
                            funcs = [l for l in lanes if l is not None]
                            if funcs:
                                mem_tables[addr] = funcs
                # movaps mem -> xmm: load (for completeness)
                elif dst.type == X86_OP_REG and src.type == X86_OP_MEM:
                    dst_name = self._xmm_name(insn, dst.reg)
                    if dst_name:
                        addr = self._resolve_mem_addr(insn, src, func_entry)
                        if addr is not None and addr in mem_tables:
                            funcs = mem_tables[addr]
                            # Pad to 2 lanes
                            while len(funcs) < 2:
                                funcs.append(None)
                            xmm[dst_name] = funcs[:2]
        return xmm, mem_tables

    def _resolve_mem_addr(self, insn, op, func_entry):
        """Resolve memory operand to concrete address if possible.
        Handles [rsp+disp], [rbp-disp]. Returns None if not resolvable.
        """
        if op.mem.base == 0:
            return None
        try:
            base_name = insn.reg_name(op.mem.base)
        except:
            return None
        # For stack-relative, we can't get absolute address without knowing rsp/rbp
        # Instead, return a symbolic key: (base, disp)
        # For the table lookup, we'll match by (base, disp) pattern
        if base_name in ('rsp', 'esp'):
            return ('rsp', op.mem.disp)
        elif base_name in ('rbp', 'ebp'):
            return ('rbp', op.mem.disp)
        return None

    def resolve_simd_table_call(self, site_addr, func_entry):
        """Resolve call *N(base,index,8) where base points to SIMD-initialized table.
        Returns set of function addresses.
        """
        insn = self.cfg.insns.get(site_addr)
        if not insn or len(insn.operands) != 1:
            return set()
        op = insn.operands[0]
        if op.type != X86_OP_MEM:
            return set()
        # Check for SIB: base + index*8
        if op.mem.index == 0 or op.mem.scale != 8:
            return set()
        try:
            base_name = insn.reg_name(op.mem.base)
        except:
            return set()
        # Analyze SIMD up to site
        xmm, mem_tables = self.analyze_function(func_entry, site_addr)
        # Find table base: look for mem_tables with matching base
        # The call is *(base + disp + index*8). The table was stored via movaps.
        # For p02: table at (rsp, 0) and (rsp, 0x10)
        disp = op.mem.disp
        # Collect all functions from tables that could be accessed
        targets = set()
        for (tbase, tdisp), funcs in mem_tables.items():
            if tbase == base_name:
                # Check if disp is within the table region
                # Table entries are 8 bytes; movaps stores 16 bytes (2 entries)
                # For simplicity, if the base matches, include all funcs from nearby tables
                # (over-approximate but sound for the benchmark)
                targets.update(funcs)
        # Also try: if we have tables at (rsp,0) and (rsp,0x10), and call is *(rsp+rax*8),
        # then it's accessing the combined table
        if base_name in ('rsp', 'esp'):
            # Collect all rsp-relative tables
            for (tbase, tdisp), funcs in mem_tables.items():
                if tbase == 'rsp':
                    targets.update(funcs)
        return {t for t in targets if t in self.func_entries}
