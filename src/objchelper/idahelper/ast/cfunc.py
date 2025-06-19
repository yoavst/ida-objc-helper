from collections.abc import Callable

import ida_hexrays
import idaapi
from ida_funcs import func_t
from ida_hexrays import CV_FAST, cexpr_t, cfunc_t, cfuncptr_t, ctree_visitor_t, lvar_t, lvars_t


def from_ea(ea: int, should_generate_pseudocode: bool = False) -> cfuncptr_t | None:
    """decompile a function"""
    f = idaapi.get_func(ea)
    if f is None:
        return None

    return from_func(f, should_generate_pseudocode)


def from_func(func: func_t, should_generate_pseudocode: bool = False) -> cfuncptr_t | None:
    """Decompile a function"""
    decompiled = idaapi.decompile(func)
    if decompiled is None:
        return None

    if should_generate_pseudocode:
        decompiled.get_pseudocode()

    return decompiled


def get_lvar_by_offset(func: cfunc_t | cfuncptr_t, offset: int) -> lvar_t | None:
    """Given a decompiled function, return the lvar located at {offset} on the stack"""
    lvars: lvars_t = func.get_lvars()
    for lv in lvars:
        if lv.get_stkoff() == offset:
            return lv
    return None


class _FinderVisitor(ctree_visitor_t):
    """Search for expressions fulfilling a condition in ctree"""

    def __init__(self, match_fn: Callable[[cexpr_t], bool]):
        super().__init__(CV_FAST)
        self.match_fn: Callable[[cexpr_t], bool] = match_fn
        self.found: list[cexpr_t] = []

    def visit_expr(self, expr: cexpr_t) -> int:  # pyright: ignore[reportIncompatibleMethodOverride]
        if self.match_fn(expr):
            self.found.append(expr)
        return 0


def get_call_expression_at_ea(func: cfunc_t | cfuncptr_t, call_ea: int) -> cexpr_t | None:
    """Given a function and ea, find the call expression that are on this ea, or none if not found"""
    finder = _FinderVisitor(lambda e: e.op == ida_hexrays.cot_call)
    for insn in func.get_eamap().get(call_ea, []):
        finder.apply_to(insn, None)  # pyright: ignore[reportArgumentType]

    if len(finder.found) != 1:
        return None
    return finder.found[0]
