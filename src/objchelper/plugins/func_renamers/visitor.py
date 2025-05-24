__all__ = ["Call", "ParsedParam", "process_function_calls"]

from collections.abc import Callable
from dataclasses import dataclass

import ida_hexrays
from ida_hexrays import mba_t, mcallarg_t, minsn_t, mop_t

from objchelper.idahelper import tif
from objchelper.idahelper.microcode import mop
from objchelper.idahelper.microcode.visitors import extended_microcode_visitor_t


def process_function_calls(func_mba: mba_t, callbacks: dict[int | str, Callable[["Call"], None]]):
    """Get all calls to the given function in the current function."""
    StaticCallExtractorVisitor(callbacks).visit_function(func_mba)


# TODO: This is a hack, we should find a way to remove all consts
CHAR_POINTER_TYPES = [tif.from_c_type("char*"), tif.from_c_type("const char*"), tif.from_c_type("char* const")]

ParsedParam = str | int | None


@dataclass
class Call:
    """A call to a function"""

    func_ea: int
    """The ea of the function"""
    ea: int
    """The ea of the call instruction"""
    params_op: list[mcallarg_t]
    """The operands of the call instruction"""
    params: list[ParsedParam]
    """Parsed params of the call instruction"""
    assignee: mop_t | None

    def __str__(self):
        params_str = ", ".join([
            repr(param) if param is not None else op_param.dstr()
            for param, op_param in zip(self.params, self.params_op, strict=True)
        ])
        assignee_str = f", assignee={self.assignee.dstr()}" if self.assignee is not None else ""
        return f"Call(ea={hex(self.ea)}, params=[{params_str}]{assignee_str}"


class StaticCallExtractorVisitor(extended_microcode_visitor_t):
    def __init__(self, callbacks: dict[int | str, Callable[[Call], None]]):
        super().__init__()
        self.callbacks = callbacks

    def _visit_insn(self, ins: minsn_t) -> int:
        if ins.opcode != ida_hexrays.m_call:
            return 0

        if ins.l.t == ida_hexrays.mop_v:
            match = ins.l.g
        elif ins.l.t == ida_hexrays.mop_h:
            match = ins.l.helper
        else:
            return 0

        callback = self.callbacks.get(match)
        if callback is None:
            return 0

        params: list[mcallarg_t] = list(ins.d.f.args)
        parsed_params = [parse_param(param) for param in params]
        assignee = try_extract_assignee(self.parents)
        callback(Call(self.mba.entry_ea, ins.ea, params, parsed_params, assignee))
        return 0


def try_extract_assignee(parents: list[mop_t | minsn_t]) -> mop_t | None:
    """
    Try to extract the assignee from the parents of the call.
    """
    if not parents:
        # Direct call instruction, no assignee
        return None
    assert len(parents) >= 2, f"Expected at least 2 parents, got {len(parents)}: {[p.dstr() for p in parents]}"

    # Skip the first parent, which is the mop_d wrapper
    parent = parents[-2]
    # Mop can be a child of the following:
    # - direct instruction operand (l,r,d)
    # - function argument
    # - ref to a variable - not if we are a function call
    # - pair - never seen this so let's ignore it
    if isinstance(parent, mop_t):
        # In this case we are a function argument, therefore no assignee
        assert parent.t == ida_hexrays.mop_f, f"Expected mop_f, got {parent.dstr()}"
        return None
    # minsn_t case
    elif parent.is_like_move() or parent.opcode == ida_hexrays.m_stx:
        # Check there is an actual assignee and not a nop one
        if parent.d.t != ida_hexrays.mop_z:
            return parent.d

    # Not a move or store, no assignee
    return None


def parse_param(param: mcallarg_t) -> ParsedParam:
    """Try to parse the param to python constant"""
    if param.type in CHAR_POINTER_TYPES:
        return mop.get_str(param)
    return mop.get_const_int(param)
