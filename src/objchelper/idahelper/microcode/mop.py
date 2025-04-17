import ida_hexrays
from ida_hexrays import (
    mop_addr_t,
    mop_t,
)

from objchelper.idahelper import memory


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
        return memory.name_from_ea(mop.g)


def get_str(mop: mop_t) -> str | None:
    """Given a mop representing a string, return its value"""
    if mop.t == ida_hexrays.mop_str:
        return mop.cstr
    elif mop.is_glbaddr():
        return memory.str_from_ea(mop.a.g) or None
