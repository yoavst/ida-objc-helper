__all__ = [
    "analyze_reg_dependencies",
    "decode_instruction",
    "decode_next_instruction",
    "from_func",
    "get_register_name",
    "is_flow_instruction",
]

import functools
from collections.abc import Iterator

import ida_idp
import ida_ua
import idaapi
import idautils
from ida_funcs import func_t
from ida_ua import insn_t


@functools.cache
def _registers() -> list[str]:
    return ida_idp.ph_get_regnames()


def decode_instruction(ea: int) -> insn_t | None:
    """Decode an instruction at the given ea"""
    return idautils.DecodeInstruction(ea)


def decode_next_instruction(insn: insn_t, func: func_t) -> insn_t | None:
    """Decode the next instruction after the given insn"""
    next_ea = insn.ea + insn.size
    if next_ea >= func.end_ea:
        return None

    return decode_instruction(next_ea)


def decode_previous_instruction(insn: insn_t) -> insn_t | None:
    """Decode the previous instruction for the given insn"""
    return idautils.DecodePrecedingInstruction(insn.ea)[0]


def is_flow_instruction(insn: insn_t) -> bool:
    """Given an instruction, is it possible for it to influence the flow and not running the next instruction in memory"""
    feature = insn.get_canon_feature()
    return (feature & (idaapi.CF_CALL | idaapi.CF_STOP | idaapi.CF_JUMP)) != 0


def get_register_name(reg: int) -> str:
    """Given register index, return its name"""
    return _registers()[reg]


def from_func(func: func_t) -> Iterator[insn_t]:
    for ea in idautils.FuncItems(func.start_ea):
        insn = decode_instruction(ea)
        if insn:
            yield insn


OP_READ = 1
OP_WRITE = 2


def _get_operand_access(insn: insn_t, op_index: int) -> int:
    f = insn.get_canon_feature()
    access = 0
    if f & (ida_idp.CF_USE1 << op_index):
        access |= OP_READ
    if f & (ida_idp.CF_CHG1 << op_index):
        access |= OP_WRITE
    return access


def analyze_reg_dependencies(insn: insn_t) -> tuple[set[str], set[str]]:
    """for the instruction, return two sets: read registers and modified registers"""
    read, write = set(), set()

    for i, op in enumerate(insn.ops):  # type: ignore  # noqa: PGH003
        if op.type == ida_ua.o_void:
            continue

        access = _get_operand_access(insn, i)

        reg_name = None
        if op.type in (ida_ua.o_reg, ida_ua.o_phrase, ida_ua.o_displ, ida_ua.o_idpspec0):
            reg_name = _registers()[op.reg]

        if reg_name:
            if access & OP_READ:
                read.add(reg_name)
            if access & OP_WRITE:
                write.add(reg_name)
    return read, write
