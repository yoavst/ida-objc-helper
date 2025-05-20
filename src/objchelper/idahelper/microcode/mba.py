from collections.abc import Iterator

import ida_hexrays
import idaapi
from ida_hexrays import lvar_t, mba_ranges_t, mba_t, mblock_t


def blocks(mba: mba_t) -> Iterator[mblock_t]:
    """Create a generator of the block's instructions"""
    for i in range(mba.qty):
        yield mba.get_mblock(i)


def from_func(func_ea: int, opt_level: int = ida_hexrays.MMAT_LVARS) -> mba_t | None:
    """Get mba for a function for the given optimization level"""
    f = idaapi.get_func(func_ea)
    if f is None:
        return None
    return ida_hexrays.gen_microcode(mba_ranges_t(f), None, None, 0, opt_level)


def get_ret_lvar(mba: mba_t) -> lvar_t | None:
    """Get the return variable of the function"""
    if mba.retvaridx != -1:
        return mba.vars[mba.retvaridx]

    return None
