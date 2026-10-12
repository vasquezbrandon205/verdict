#!/usr/bin/env python3
"""VERDICT-v0.1: independent reverse-engineering pipeline (no Ghidra dependency).
Foundation: ELF loader + Capstone decoder + leader-based CFG builder.
"""
import struct
import bisect
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_REG, X86_OP_IMM, X86_OP_MEM


class ELFLoader:
    """Minimal ELF64 loader: sections, entry point, .text bytes."""
    def __init__(self, path):
        with open(path, 'rb') as f:
            self.data = f.read()
        self._parse()

    def _parse(self):
        d = self.data
        assert d[:4] == b'\x7fELF', 'not ELF'
        assert d[4] == 2, 'not 64-bit'
        (self.entry,) = struct.unpack_from('<Q', d, 0x18)
        (self.shoff,) = struct.unpack_from('<Q', d, 0x28)
        (self.shentsize, self.shnum, self.shstrndx) = struct.unpack_from('<HHH', d, 0x3A)
        self.sections = []
        for i in range(self.shnum):
            off = self.shoff + i * self.shentsize
            (name_idx, stype, flags, addr, offset, size) = struct.unpack_from('<IIQQQQ', d, off)
            self.sections.append({'idx': i, 'name_idx': name_idx, 'type': stype,
                                  'flags': flags, 'addr': addr, 'offset': offset, 'size': size})
        strtab = self.sections[self.shstrndx]
        for s in self.sections:
            end = d.index(b'\x00', strtab['offset'] + s['name_idx'])
            s['name'] = d[strtab['offset'] + s['name_idx']:end].decode('ascii', 'replace')
        self.by_name = {s['name']: s for s in self.sections}

    def section_bytes(self, name):
        s = self.by_name[name]
        return self.data[s['offset']:s['offset'] + s['size']]

    def vaddr_to_offset(self, vaddr):
        for s in self.sections:
            if s['addr'] <= vaddr < s['addr'] + s['size'] and s['type'] != 8:
                return s['offset'] + (vaddr - s['addr'])
        return None


class Decoder:
    def __init__(self):
        self.cs = Cs(CS_ARCH_X86, CS_MODE_64)
        self.cs.detail = True

    def decode(self, code, base_addr):
        return list(self.cs.disasm(code, base_addr))


class BasicBlock:
    def __init__(self, start):
        self.start = start
        self.insns = []
        self.succs = []
        self.is_return = False

    @property
    def end(self):
        return self.insns[-1].address + self.insns[-1].size if self.insns else self.start


class CFG:
    """Leader-based CFG builder."""
    JCC = {'jo', 'jno', 'jb', 'jnae', 'jc', 'jnb', 'jae', 'jnc', 'jz', 'je',
           'jnz', 'jne', 'jbe', 'jna', 'jnbe', 'ja', 'js', 'jns', 'jp', 'jpe',
           'jnp', 'jpo', 'jl', 'jnge', 'jnl', 'jge', 'jle', 'jng', 'jnle', 'jg'}
    CALLS = {'call', 'callq'}
    RETS = {'ret', 'retq', 'retf', 'iret', 'iretd', 'iretq'}
    HALTS = {'hlt', 'ud2', 'int3'}

    def __init__(self, decoder, code, base_addr):
        self.decoder = decoder
        self.code = code
        self.base = base_addr
        self.insns = {}
        self.addrs = []
        for i in decoder.decode(code, base_addr):
            self.insns[i.address] = i
            self.addrs.append(i.address)
        self.addrs.sort()
        self.blocks = {}
        self.direct_calls = []
        self.indirect_calls = []
        self.indirect_jumps = []

    def _is_jcc(self, insn):
        return insn.mnemonic in self.JCC

    def _is_jmp(self, insn):
        return insn.mnemonic in ('jmp', 'jmpq')

    def _is_call(self, insn):
        return insn.mnemonic in self.CALLS

    def _is_ret(self, insn):
        return insn.mnemonic in self.RETS

    def _is_halt(self, insn):
        return insn.mnemonic in self.HALTS

    def _branch_target(self, insn):
        if len(insn.operands) != 1:
            return None
        op = insn.operands[0]
        if op.type == X86_OP_IMM:
            return op.imm
        return None

    def build(self):
        leaders = set()
        if self.addrs:
            leaders.add(self.addrs[0])
        for addr in self.addrs:
            insn = self.insns[addr]
            if self._is_jcc(insn) or self._is_jmp(insn):
                tgt = self._branch_target(insn)
                if tgt is not None and tgt in self.insns:
                    leaders.add(tgt)
                elif self._is_jmp(insn) and tgt is None:
                    self.indirect_jumps.append(addr)
                nxt = addr + insn.size
                if nxt in self.insns:
                    leaders.add(nxt)
            elif self._is_call(insn):
                tgt = self._branch_target(insn)
                if tgt is not None:
                    if tgt in self.insns:
                        leaders.add(tgt)
                    self.direct_calls.append((addr, tgt))
                else:
                    self.indirect_calls.append(addr)
                nxt = addr + insn.size
                if nxt in self.insns:
                    leaders.add(nxt)
            elif self._is_ret(insn) or self._is_halt(insn):
                nxt = addr + insn.size
                if nxt in self.insns:
                    leaders.add(nxt)
        leaders = sorted(leaders)
        for i, start in enumerate(leaders):
            end = leaders[i + 1] if i + 1 < len(leaders) else None
            bb = BasicBlock(start)
            addr = start
            while addr in self.insns and (end is None or addr < end):
                insn = self.insns[addr]
                bb.insns.append(insn)
                if self._is_jcc(insn):
                    tgt = self._branch_target(insn)
                    fall = addr + insn.size
                    if tgt is not None:
                        bb.succs.append(tgt)
                    if fall in self.insns:
                        bb.succs.append(fall)
                    break
                elif self._is_jmp(insn):
                    tgt = self._branch_target(insn)
                    if tgt is not None:
                        bb.succs.append(tgt)
                    break
                elif self._is_ret(insn) or self._is_halt(insn):
                    bb.is_return = self._is_ret(insn)
                    break
                addr += insn.size
            self.blocks[start] = bb
        return self.blocks

    @staticmethod
    def func_containing(addr, func_entries):
        i = bisect.bisect_right(func_entries, addr) - 1
        return func_entries[i] if i >= 0 else None
