import ida_hexrays
import ida_name
from ida_hexrays import (
    mop_addr_t,
    mop_t,
)


def from_global_ref(ea: int) -> mop_t:
    """Given `ea` of a global address, create a mop that represents a `(void*)ea`"""
    mop = mop_t()
    mop.t = ida_hexrays.mop_a
    mop.a = mop_addr_t()
    mop.a.t = ida_hexrays.mop_v
    mop.a.g = ea
    mop.size = 8
    return mop


def get_name(mop: mop_t) -> str | None:
    """Given a mop representing a symbol/helper, return its name"""
    if mop.helper is not None:
        return mop.helper
    elif mop.g is not None:
        ea = mop.g
        return ida_name.get_name(ea)
