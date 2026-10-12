#!/usr/bin/env python3
"""VERDICT-v0.2 vtable analysis for C++ virtual dispatch.
Finds vtables via lea patterns, parses slots, resolves virtual calls.
"""
import struct
from capstone.x86 import X86_OP_REG, X86_OP_IMM, X86_OP_MEM


class VtableAnalyzer:
    def __init__(self, cfg, func_entries, loader):
        self.cfg = cfg
        self.func_entries = set(func_entries)
        self.loader = loader
        self.vtables = {}  # vtable_addr -> [func_addr, ...] (slots)
        self._find_vtables()

    def _find_vtables(self):
        """Find vtables via lea to .data.rel.ro with function pointers."""
        if not self.loader:
            return
        # Get .data.rel.ro section
        sec = self.loader.by_name.get('.data.rel.ro')
        if not sec:
            sec = self.loader.by_name.get('.data')
        if not sec:
            return
        data_start = sec['addr']
        data = self.loader.section_bytes('.data.rel.ro' if '.data.rel.ro' in self.loader.by_name else '.data')
        # Find lea instructions targeting this section
        for addr, insn in self.cfg.insns.items():
            if insn.mnemonic != 'lea' or len(insn.operands) != 2:
                continue
            src = insn.operands[1]
            if src.type != X86_OP_MEM:
                continue
            try:
                base = insn.reg_name(src.mem.base)
            except:
                continue
            if base != 'rip':
                continue
            tgt = addr + insn.size + src.mem.disp
            # Check if tgt is in data section
            if not (data_start <= tgt < data_start + len(data)):
                continue
            # Try to parse as vtable: read 8-byte pointers
            slots = []
            offset = tgt - data_start
            for i in range(10):  # max 10 slots
                if offset + 8 > len(data):
                    break
                (val,) = struct.unpack_from('<Q', data, offset)
                # Check if val is a function entry (in .text)
                if val in self.func_entries:
                    slots.append(val)
                    offset += 8
                else:
                    # Not a function pointer; stop (vtable ends)
                    # But allow for 0 (pure virtual) or small ints?
                    # For now, stop at first non-function
                    break
            if len(slots) >= 1:
                # Likely a vtable (has at least 1 function pointer)
                self.vtables[tgt] = slots

    def resolve_virtual_call(self, site_addr, func_entry):
        """Try to resolve a virtual call site.
        Patterns:
        - mov (%rax),%rax; [add $N,%rax]; mov (%rax),%rdx; call *%rdx (O0)
        - mov (%rbx),%rax; call *(%rax) or call *N(%rax) (O2/O3)
        Returns (targets:set, slot:int) or (set(), None)."""
        # Find the call instruction
        call_insn = self.cfg.insns.get(site_addr)
        if not call_insn or 'call' not in call_insn.mnemonic:
            return set(), None
        if len(call_insn.operands) != 1:
            return set(), None
        op = call_insn.operands[0]
        # Case 1: memory-indirect call: call *N(%reg) (O2/O3 pattern)
        if op.type == X86_OP_MEM:
            return self._resolve_mem_indirect_vcall(site_addr, op)
        # Case 2: register-indirect: call *%reg (O0 pattern)
        if op.type != X86_OP_REG:
            return set(), None
        # Walk backward to find the slot load
        # Look for: mov (%rax),%rdx  or  mov 0xN(%rax),%rdx
        # Or: add $N,%rax; mov (%rax),%rdx
        site_block_start, site_bb = self._find_block(site_addr)
        if not site_bb:
            return set(), None
        # Find index of call
        call_idx = None
        for i, ins in enumerate(site_bb.insns):
            if ins.address == site_addr:
                call_idx = i
                break
        if call_idx is None:
            return set(), None
        # Walk backward to find the slot load
        # Look for: mov (%rax),%rdx  or  mov 0xN(%rax),%rdx
        # Where %rdx is the register used in the call
        site_block_start, site_bb = self._find_block(site_addr)
        if not site_bb:
            return set(), None
        # Find index of call and get the target register
        call_idx = None
        call_reg = None
        for i, ins in enumerate(site_bb.insns):
            if ins.address == site_addr:
                call_idx = i
                if len(ins.operands) == 1 and ins.operands[0].type == X86_OP_REG:
                    call_reg = ins.reg_name(ins.operands[0].reg)
                break
        if call_idx is None or call_reg is None:
            return set(), None
        # Walk backward to find definition of call_reg
        # First, collect all add offsets in the block (forward pass)
        add_offsets = {}
        for insn in site_bb.insns:
            if insn.address >= site_addr:
                break
            if insn.mnemonic == 'add' and len(insn.operands) == 2:
                dst, src = insn.operands[0], insn.operands[1]
                if dst.type == X86_OP_REG and src.type == X86_OP_IMM:
                    try:
                        reg_name = insn.reg_name(dst.reg)
                        # Only track if the add is before the mov we're looking for
                        # (simplified: track all, use the last one before the mov)
                        add_offsets[reg_name] = src.imm
                    except:
                        pass
        slot = None
        vptr_reg = None
        for i in range(call_idx - 1, -1, -1):
            insn = site_bb.insns[i]
            m = insn.mnemonic
            if m == 'mov' and len(insn.operands) == 2:
                dst, src = insn.operands[0], insn.operands[1]
                if dst.type == X86_OP_REG and src.type == X86_OP_MEM:
                    try:
                        dst_name = insn.reg_name(dst.reg)
                    except:
                        continue
                    # Only consider defs of the call register
                    if dst_name != call_reg:
                        continue
                    try:
                        src_base = insn.reg_name(src.mem.base) if src.mem.base != 0 else ''
                    except:
                        continue
                    # Check if this is loading from vptr
                    # Pattern: mov (%rax),%rdx -> slot 0
                    # Pattern: mov 0x8(%rax),%rdx -> slot 1
                    # Pattern: add $0x8,%rax; mov (%rax),%rdx -> slot 1
                    # Skip stack loads ([rbp-X] or [rsp+X]) - those are object pointers, not vtable slots
                    if src_base in ('rbp', 'rsp', 'ebp', 'esp'):
                        continue
                    if src.mem.index == 0:  # no index
                        disp = src.mem.disp
                        # Add any offset from 'add' instructions on the base reg
                        disp += add_offsets.get(src_base, 0)
                        if disp % 8 == 0 and disp >= 0:
                            slot = disp // 8
                            vptr_reg = src_base
                            break
        if slot is None:
            return set(), None
        # Now find which vtables could be used
        # Simplified: return all vtables' slot entries (over-approximate)
        # TODO: track which vtable is in the object
        targets = set()
        for vt_addr, slots in self.vtables.items():
            if 0 <= slot < len(slots):
                targets.add(slots[slot])
        return targets, slot

    def _find_block(self, addr):
        for bstart, bb in self.cfg.blocks.items():
            for ins in bb.insns:
                if ins.address == addr:
                    return bstart, bb
        return None, None

    def _resolve_mem_indirect_vcall(self, site_addr, op):
        """Resolve call *N(%reg) where reg holds vptr.
        Pattern: mov (%obj),%reg; call *N(%reg)
        N/8 = slot number.
        """
        # Get base register and displacement
        if op.mem.base == 0:
            return set(), None
        try:
            # Need insn to get reg name; get from cfg
            call_insn = self.cfg.insns.get(site_addr)
            base_reg = call_insn.reg_name(op.mem.base)
        except:
            return set(), None
        disp = op.mem.disp
        # Check for index (should not have index for vtable)
        if op.mem.index != 0:
            return set(), None
        if disp % 8 != 0 or disp < 0:
            return set(), None
        slot = disp // 8
        # Verify that base_reg holds a vptr by checking preceding mov
        # Pattern: mov (%obj_reg), %base_reg
        site_bstart, site_bb = self._find_block(site_addr)
        if not site_bb:
            return set(), None
        # Find call index
        call_idx = None
        for i, ins in enumerate(site_bb.insns):
            if ins.address == site_addr:
                call_idx = i
                break
        if call_idx is None:
            return set(), None
        # Look backward for mov (%X), %base_reg
        vptr_verified = False
        for i in range(call_idx - 1, -1, -1):
            insn = site_bb.insns[i]
            if insn.mnemonic == 'mov' and len(insn.operands) == 2:
                dst, src = insn.operands[0], insn.operands[1]
                if dst.type == X86_OP_REG and src.type == X86_OP_MEM:
                    try:
                        dst_name = insn.reg_name(dst.reg)
                    except:
                        continue
                    if dst_name == base_reg:
                        # Check if src is (%reg) - vptr load
                        if src.mem.disp == 0 and src.mem.index == 0:
                            vptr_verified = True
                            break
                        # If it's another pattern, stop searching
                        break
            # Don't go too far back
            if call_idx - i > 5:
                break
        if not vptr_verified:
            return set(), None
        # Resolve slot across all vtables
        targets = set()
        for vt_addr, slots in self.vtables.items():
            if 0 <= slot < len(slots):
                targets.add(slots[slot])
        return targets, slot
