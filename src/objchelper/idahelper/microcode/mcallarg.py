from ida_hexrays import (
    mcallarg_t,
    mop_t,
)
from ida_typeinf import tinfo_t


def from_mop(mop: mop_t, arg_type: tinfo_t) -> mcallarg_t:
    """Given existing `mop`, wrap it in a `callarg` of type `arg_type`"""
    arg = mcallarg_t()
    arg.copy_mop(mop)
    arg.type = arg_type
    return arg
