import ida_xref
import idaapi
import idautils
from ida_funcs import func_t


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
