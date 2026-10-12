#!/usr/bin/env python3
"""VERDICT-v0.4 minimal cross-module FP resolution for p10 pattern.
Pattern:
  lib: setter(param) { global = param; }
  lib: user() { fp = global; fp(); }  // S1
  main: setter(target);  // via PLT
Resolution: target flows main -> lib.setter(param) -> lib.global -> lib.user(S1)
"""
import subprocess
import re
from capstone.x86 import X86_OP_REG, X86_OP_IMM, X86_OP_MEM


def get_exports(binary_path):
    """Get exported function symbols: name -> address."""
    exports = {}
    try:
        out = subprocess.run(
            ['nm', '-D', '--defined-only', binary_path],
            capture_output=True, text=True, timeout=10
        ).stdout
        for line in out.splitlines():
            m = re.match(r'([0-9a-f]+)\s+T\s+(\S+)', line)
            if m:
                addr, name = m.groups()
                exports[name] = int(addr, 16)
    except Exception:
        pass
    return exports


def get_plt_targets(binary_path):
    """Get PLT call targets: call_addr -> symbol name.
    Uses objdump to find 'call XX <name@plt>'.
    """
    plt_calls = {}
    try:
        out = subprocess.run(
            ['objdump', '-d', binary_path],
            capture_output=True, text=True, timeout=30
        ).stdout
        for line in out.splitlines():
            # Format: "  11ce:\te8 bd fe ff ff \tcall   1090 <register_handler@plt>"
            m = re.search(r'^\s*([0-9a-f]+):.*\tcall\s+[0-9a-f]+\s+<(\S+)@plt>', line)
            if m:
                addr, name = m.groups()
                plt_calls[int(addr, 16)] = name
    except Exception:
        pass
    return plt_calls


class CrossModuleResolver:
    """Resolves cross-module FP flows for the p10 pattern."""
    
    def __init__(self, main_path, lib_path):
        self.main_path = main_path
        self.lib_path = lib_path
        self.lib_exports = get_exports(lib_path)
        self.main_plt = get_plt_targets(main_path)
    
    def find_setter_callers(self, setter_name):
        """Find call sites in main that call setter_name via PLT.
        Returns list of call addresses.
        """
        callers = []
        for call_addr, name in self.main_plt.items():
            if name == setter_name:
                callers.append(call_addr)
        return callers
