__all__ = ["try_add_block_arg_byref_to_func"]

from collections.abc import Callable, Iterator
from dataclasses import dataclass

import ida_hexrays
from ida_hexrays import (
    cexpr_t,
    cfunc_t,
    cinsn_t,
    lvar_saved_info_t,
    lvar_t,
    lvar_uservec_t,
    lvars_t,
    mba_t,
    minsn_t,
    mop_t,
    user_lvar_modifier_t,
)
from ida_typeinf import tinfo_t

from objchelper.idahelper import tif, widgets
from objchelper.idahelper.ast import cfunc
from objchelper.idahelper.microcode import mba, mblock, mop
from objchelper.plugins.objc_block.block_arg_byref import (
    BlockArgByRefField,
    create_block_arg_byref_type,
    is_block_arg_byref_type,
)
from objchelper.plugins.objc_block.utils import StructFieldAssignment, get_struct_fields_assignments

IDA_BLOCK_TYPE_NAME_PREFIX = "Block_layout_"
IDA_BLOCK_TYPE_BUILTIN_FIELD_NAMES = {
    "isa",
    "flags",
    "reserved",
    "invoke",
    "description",
    "copy_helper",
    "dispose_helper",
}

CLANG_BLOCK_HAS_COPY_DISPOSE = 1 << 25


class block_arg_by_ref_lvars_modifiers_t(user_lvar_modifier_t):
    def __init__(self, new_types: dict[str, tinfo_t]):
        super().__init__()
        self._new_types = new_types

    def modify_lvars(self, lvinf: lvar_uservec_t) -> bool:
        if len(self._new_types) == 0:
            return False

        for lvar in lvinf.lvvec:
            lvar: lvar_saved_info_t
            if lvar.name in self._new_types:
                lvar.type = self._new_types[lvar.name]

        return True


def try_add_block_arg_byref_to_func(func: cfunc_t):
    block_lvars = get_ida_block_lvars(func)
    if not block_lvars:
        return 0

    # Scan the cfunc for possible ref args for blocks
    assignments = get_struct_fields_assignments(func, block_lvars)
    by_ref_args_candidates: dict[int, lvar_t] = {}
    for lvar in block_lvars:
        if lvar.name not in assignments:
            print(f"[Error] Block variable {lvar.name} has no assignments")
            continue

        for stack_offset, _ in get_by_ref_args_for_block_candidates(lvar, assignments[lvar.name]):
            by_ref_args_candidates[stack_offset] = lvar

    # scan the microcode using the offsets to see if any of them is a start of a by ref arg struct.
    results = ScanForRefArg(set(by_ref_args_candidates.keys())).scan(func.mba)
    changes: dict[str, tinfo_t] = {}
    for result in results:
        new_type = create_block_arg_byref_type(result.initialization_ea, result.variable.size, result.has_helpers)
        lvar = cfunc.get_lvar_by_offset(func, result.initial_stack_offset)
        changes[lvar.name] = new_type
        # We need to find the lvar that matches the offset

        # Rename variable so IDA would consider it modified
        ida_hexrays.rename_lvar(func.entry_ea, lvar.name, lvar.name)

    # Apply new types for the lvars
    modifier = block_arg_by_ref_lvars_modifiers_t(changes)
    ida_hexrays.modify_user_lvars(func.entry_ea, modifier)
    widgets.refresh_pseudocode_widgets()


@dataclass
class ScanForBlockArgByRefState:
    current_field: BlockArgByRefField
    initialization_ea: int | None
    has_helpers: bool | None
    initial_stack_offset: int | None
    isa: mop_t | None
    flags: mop_t | None
    size: mop_t | None
    helper_keep: mop_t | None
    helper_dispose: mop_t | None
    variable: mop_t | None

    @staticmethod
    def initial() -> "ScanForBlockArgByRefState":
        return ScanForBlockArgByRefState(
            current_field=BlockArgByRefField.ISA,
            initialization_ea=None,
            has_helpers=None,
            initial_stack_offset=None,
            isa=None,
            flags=None,
            size=None,
            helper_keep=None,
            helper_dispose=None,
            variable=None,
        )

    def expected_offset(self) -> int:
        """Returns the expected relative offset for the next field to read"""
        assert self.initial_stack_offset is not None, "stack_offset must be set before calling expected_offset"

        return self.initial_stack_offset + self.current_field.get_offset(self.has_helpers)


class ScanForRefArg:
    def __init__(self, possible_stack_offsets: set[int]):
        self._state = ScanForBlockArgByRefState.initial()
        self._possible_stack_offsets = possible_stack_offsets
        self._results: list[ScanForBlockArgByRefState] = []
        self._state_handlers: dict[BlockArgByRefField, Callable[[mop_t, int], None]] = {
            BlockArgByRefField.ISA: self._isa,
            BlockArgByRefField.FORWARDING: self._forwarding,
            BlockArgByRefField.FLAGS: self._flags,
            BlockArgByRefField.SIZE: self._size,
            BlockArgByRefField.HELPER_KEEP: self._helper_keep,
            BlockArgByRefField.HELPER_DISPOSE: self._helper_dispose,
            BlockArgByRefField.VARIABLE: self._variable,
        }

    def scan(self, func_mba: mba_t) -> list[ScanForBlockArgByRefState]:
        # Clean state
        self._state = ScanForBlockArgByRefState.initial()
        self._results = []

        for block in mba.blocks(func_mba):
            for insn in mblock.instructions(block):
                self._on_instruction(insn)
        return self._results

    def _on_instruction(self, insn: minsn_t) -> None:
        # initialization of the block by reg arg is done using mov only.
        if insn.opcode != ida_hexrays.m_mov:
            self._state = ScanForBlockArgByRefState.initial()
            return

        # Check if the instruction is a mov to a stack variable
        offset = mop.get_stack_offset(insn.d)
        if offset is None:
            self._state = ScanForBlockArgByRefState.initial()
            return

        # Check if the write offset is correct
        if self._state.initial_stack_offset is not None and offset != self._state.expected_offset():
            self._state = ScanForBlockArgByRefState.initial()
            return

        if self._state.initialization_ea is None:
            self._state.initialization_ea = insn.ea

        self._state_handlers[self._state.current_field](insn.l, offset)

    def _isa(self, value: mop_t, offset: int) -> None:
        if offset not in self._possible_stack_offsets or value.size != 8:
            self._state = ScanForBlockArgByRefState.initial()
            return

        self._state.current_field = BlockArgByRefField.FORWARDING
        self._state.initial_stack_offset = offset
        self._state.isa = value

    def _forwarding(self, value: mop_t, _offset: int) -> None:
        if value.size != 8 or mop.get_stack_offset(value) != self._state.initial_stack_offset:
            self._state = ScanForBlockArgByRefState.initial()
            return

        self._state.current_field = BlockArgByRefField.FLAGS
        self._state.forwarding = value

    def _flags(self, value: mop_t, _offset: int) -> None:
        # Here we can encounter either a DWORD assignment for flags,
        # or a QWORD assignment for both the flags and size.
        if value.size not in (4, 8):
            self._state = ScanForBlockArgByRefState.initial()
            return

        numeric_value = mop.get_const_int(value, is_signed=False)
        if numeric_value is None:
            self._state = ScanForBlockArgByRefState.initial()
            return

        if value.size == 4:
            self._state.current_field = BlockArgByRefField.SIZE
            self._state.flags = value
            flags = numeric_value
        else:
            flags = numeric_value & 0xFF_FF_FF_FF
            size = (numeric_value >> 32) & 0xFFFF
            # Create new mop for size and flags
            self._state.flags = mop.from_const_value(flags, 4)
            self._state.size = mop.from_const_value(size, 4)

        if flags & CLANG_BLOCK_HAS_COPY_DISPOSE:
            self._state.has_helpers = True
            self._state.current_field = BlockArgByRefField.HELPER_KEEP
        else:
            self._state.has_helpers = False
            self._state.current_field = BlockArgByRefField.VARIABLE

    def _size(self, value: mop_t, _offset: int) -> None:
        if value.size != 4:
            self._state = ScanForBlockArgByRefState.initial()
            return

        # Check that value is a constant
        numeric_value = mop.get_const_int(value, is_signed=False)
        if numeric_value is None:
            self._state = ScanForBlockArgByRefState.initial()
            return

        self._state.size = value

        # Flags cannot be none because we checked it before
        flags = mop.get_const_int(self._state.flags, is_signed=False)
        if flags & CLANG_BLOCK_HAS_COPY_DISPOSE:
            self._state.has_helpers = True
            self._state.current_field = BlockArgByRefField.HELPER_KEEP
        else:
            self._state.has_helpers = False
            self._state.current_field = BlockArgByRefField.VARIABLE

    def _helper_keep(self, value: mop_t, _offset: int) -> None:
        if value.size != 8 or value.is_glbaddr():
            self._state = ScanForBlockArgByRefState.initial()
            return

        self._state.helper_keep = value
        self._state.current_field = BlockArgByRefField.HELPER_DISPOSE

    def _helper_dispose(self, value: mop_t, _offset: int) -> None:
        if value.size != 8 or value.is_glbaddr():
            self._state = ScanForBlockArgByRefState.initial()
            return

        self._state.helper_keep = value
        self._state.current_field = BlockArgByRefField.VARIABLE

    def _variable(self, value: mop_t, _offset: int) -> None:
        self._state.variable = value
        self._results.append(self._state)

        # Reset the state
        self._state = ScanForBlockArgByRefState.initial()


def get_by_ref_args_for_block_candidates(
    lvar: lvar_t, assignments: list[StructFieldAssignment]
) -> list[tuple[int, cinsn_t]]:
    """For each assignment to a block argument, if it is a reference to a stack offset, return the stack offset"""
    possible_stack_offsets = []
    for assignment in get_args_assignments_to_block(lvar, assignments):
        # Find assignments that are refs to the stack: "block.lvar2 = &v8
        expr = assignment.expr
        if expr.op != ida_hexrays.cot_ref:
            continue
        refed_expr: cexpr_t = expr.x
        if refed_expr.op != ida_hexrays.cot_var:
            continue
        # Check if the variable is not already handled
        if is_block_arg_byref_type(refed_expr.v.getv().type()):
            continue
        # Return the stack offset of the variable
        stack_offset: int = refed_expr.v.getv().get_stkoff()
        if stack_offset == -1:
            continue
        possible_stack_offsets.append((stack_offset, assignment.insn))
    return possible_stack_offsets


def get_args_assignments_to_block(
    lvar: lvar_t, assignments: list[StructFieldAssignment]
) -> Iterator[StructFieldAssignment]:
    """Return all assignments to the block variable that are not builtin fields (aka block arguments)"""
    lvar_type = lvar.type()
    for assignment in assignments:
        member = tif.get_member(lvar_type, assignment.offset)
        if member.name in IDA_BLOCK_TYPE_BUILTIN_FIELD_NAMES:
            continue
        yield assignment


def get_ida_block_lvars(func: cfunc_t) -> list[lvar_t]:
    """Get all Obj-C block variables in the function"""
    lvars: lvars_t = func.get_lvars()
    block_lvars: list[lvar_t] = []
    for var in lvars:
        # noinspection PyTypeChecker
        type_name: str = var.type().get_type_name()
        if type_name is not None and type_name.startswith(IDA_BLOCK_TYPE_NAME_PREFIX):
            block_lvars.append(var)

    return block_lvars
