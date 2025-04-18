import ida_hexrays
from ida_hexrays import cexpr_t

from objchelper.idahelper import memory


def get_call_name(call_expr: cexpr_t) -> str | None:
    assert call_expr.op == ida_hexrays.cot_call, "Expected a call expression"
    called_func: cexpr_t = call_expr.x
    if called_func.op == ida_hexrays.cot_helper:
        return called_func.helper
    elif called_func.op == ida_hexrays.cot_obj:
        return memory.name_from_ea(called_func.obj_ea)

    return None


def strip_casts(expr: cexpr_t) -> cexpr_t:
    """Strip casts from the expression."""
    while expr.op == ida_hexrays.cot_cast:
        expr = expr.x
    return expr
