import functools

import ida_idp
from ida_hexrays import reg2mreg


@functools.cache
def cs_reg() -> int:
    """Returns the mreg id of the CS register"""
    return reg2mreg(ida_idp.ph_get_regnames().index("CS"))
