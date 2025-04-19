import ida_hexrays
from ida_hexrays import cexpr_t, cinsn_t


def from_expr(expr: cexpr_t, ea: int) -> cinsn_t:
    """Create a cinsn_t from a cexpr_t."""
    new_item = cinsn_t()
    new_item.op = ida_hexrays.cit_expr
    new_item.cexpr = expr
    new_item.thisown = False
    new_item.ea = ea
    return new_item
