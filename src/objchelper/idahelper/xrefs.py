import ida_hexrays
import ida_xref
import idaapi
import idautils
from ida_funcs import func_t
from ida_hexrays import minsn_t, mop_t

from objchelper.idahelper import strings
from objchelper.idahelper.microcode import mba
from objchelper.idahelper.microcode.visitors import extended_microcode_visitor_t


def get_xrefs_to(ea: int, is_data: bool = False) -> list[int]:
    """Get all xrefs to the given EA"""
    return [xref.frm for xref in idautils.XrefsTo(ea, ida_xref.XREF_DATA if is_data else 0)]


def func_xrefs_to(func_ea: int) -> set[int]:
    """Get all xrefs to the given EA, grouped by function"""
    xrefs_in_funcs = set()
    for xref_ea in get_xrefs_to(func_ea):
        func: func_t = idaapi.get_func(xref_ea)
        if func is not None:
            xrefs_in_funcs.add(func.start_ea)
    return xrefs_in_funcs


def find_func_containing_string(s: str) -> int | None:
    """Assume there is a single function that contains s, return the EA of call function"""
    # There might be multiple references to the string, so we need to find the one that is inside a function
    for item in strings.find_strs(s):
        for xref_ea in get_xrefs_to(item.ea):
            func: func_t = idaapi.get_func(xref_ea)
            if func is not None:
                return func.start_ea
    return None


def find_static_caller_for_string(s: str) -> int | None:
    """Assume there is a single call(..., s, ...) in code, return the EA of call function"""
    # There might be multiple references to the string, so we need to find the one that is a call
    for item in strings.find_strs(s):
        for func_xref in func_xrefs_to(item.ea):
            finder = CallFinderForEa(item.ea)
            func = mba.from_func(func_xref)
            if func is None:
                print("[Error] Could not build mba for func", hex(func_xref))
                continue
            finder.visit_function(func)
            if finder.result is not None:
                return finder.result

    return None


class CallFinderForEa(extended_microcode_visitor_t):
    def __init__(self, ea: int):
        super().__init__()
        self._ea = ea
        self.result: int | None = None

    def _visit_mop(self, op: mop_t) -> int:
        if op.t == ida_hexrays.mop_v and op.g == self._ea:
            parent = self.parents[-1]
            if not isinstance(parent, mop_t) or parent.t != ida_hexrays.mop_a:
                # If the parent is not an argument, we are not interested in this reference
                print(
                    f"[Warning] Found a reference to the EA that is not a var ref, skipping at {self.top_ins.ea:#x} - {self.top_ins.dstr()}"
                )
                return 0

            parent_args = self.parents[-2]
            if not isinstance(parent_args, mop_t) or parent_args.t != ida_hexrays.mop_f:
                # If the parent is not an instruction, we are not interested in this reference
                print(
                    f"[Warning] Found a reference to the EA that is not a function arguments, skipping at {self.top_ins.ea:#x} - {self.top_ins.dstr()}"
                )
                return 0

            parent_call = self.parents[-3]
            if not isinstance(parent_call, minsn_t) or parent_call.opcode != ida_hexrays.m_call:
                # If the parent is not a call instruction, we are not interested in this reference
                print(
                    f"[Warning] Found a reference to the EA that is not a call instruction, skipping: {parent_call.dstr()}"
                )
                return 0

            caller: mop_t = parent_call.l
            if caller.t != ida_hexrays.mop_v:
                print(f"[Warning] The call is not static, skipping: {parent_call.dstr()}")
                return 0

            self.result = caller.g
            return 1

        return 0
