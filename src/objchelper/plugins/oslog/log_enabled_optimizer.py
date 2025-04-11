__all__ = ["os_log_enabled_optimizer_t"]

import re

import ida_hexrays
from ida_hexrays import (
    mblock_t,
    mcallinfo_t,
    minsn_t,
    mop_t,
    mop_visitor_t,
)

from objchelper.base.utils import CounterMixin, match
from objchelper.idahelper.microcode import minsn

from . import os_log

FUNCTIONS_TO_REPLACE_WITH_HELPER: list[str | re.Pattern] = [
    "_os_log_type_enabled",
    re.compile(r"_os_log_type_enabled_(\d+)"),
]

LOG_TYPE_INDEX = 1


class mop_optimizer_t(mop_visitor_t, CounterMixin):
    def visit_mop(self, op: mop_t, tp, is_target: bool) -> int:
        # No assignment dest, we want a call instruction
        if not is_target and op.d is not None:
            self.visit_instruction_mop(op)
        return 0

    def visit_instruction_mop(self, op: mop_t) -> None:
        # We only want calls
        insn: minsn_t = op.d
        if insn.opcode != ida_hexrays.m_call:
            return

        # Calls with names
        name = minsn.get_func_name_of_call(insn)
        if name is None:
            return

        # If it should be optimized to first arg, optimize
        if match(FUNCTIONS_TO_REPLACE_WITH_HELPER, name):
            fi: mcallinfo_t = insn.d.f
            if fi.args.empty():
                # No arguments, probably IDA have not optimized it yet
                return

            # Log type
            log_type_arg = fi.args.at(LOG_TYPE_INDEX)
            if log_type_arg.t != ida_hexrays.mop_n:
                return
            log_type = log_type_arg.unsigned_value()

            # Change name
            insn.l.make_helper(f"oslog_{os_log.log_type_to_str(log_type)}_enabled")
            self.count()
            # Remove arguments
            fi.args.clear()
            fi.solid_args = 0
            self.count()


class os_log_enabled_optimizer_t(ida_hexrays.optinsn_t):
    def func(self, blk: mblock_t, ins: minsn_t, optflags: int) -> int:
        # Let IDA reconstruct the calls before
        if blk.mba.maturity < ida_hexrays.MMAT_CALLS:
            return 0

        mop_optimizer = mop_optimizer_t(blk.mba, blk)
        ins.for_all_ops(mop_optimizer)
        changes = mop_optimizer.cnt
        if changes:
            blk.mark_lists_dirty()
            blk.mba.verify(True)
        return changes
