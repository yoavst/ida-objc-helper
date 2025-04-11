import ida_hexrays
from ida_hexrays import (
    minsn_t,
)

from . import mop


def get_func_name_of_call(insn: minsn_t) -> str | None:
    """Given a call instruction, return the name of the called function"""
    assert insn.opcode == ida_hexrays.m_call, "Not a call instruction"
    return mop.get_name(insn.l)
