__all__ = ["FLAG_BLOCK_HAS_COPY_DISPOSE", "block_member_is_arg_field", "get_ida_block_lvars", "is_block_type"]

from ida_hexrays import (
    cfunc_t,
    lvar_t,
)
from ida_typeinf import tinfo_t, udm_t

IDA_BLOCK_TYPE_NAME_PREFIX = "Block_layout_"
IDA_BLOCK_TYPE_BASE_FIELD_NAMES = {
    "isa",
    "flags",
    "reserved",
    "invoke",
    "description",
    "copy_helper",
    "dispose_helper",
}

FLAG_BLOCK_HAS_COPY_DISPOSE = 1 << 25


def get_ida_block_lvars(func: cfunc_t) -> list[lvar_t]:
    """Get all Obj-C block variables in the function"""
    return [lvar for lvar in func.get_lvars() if is_block_type(lvar.type())]


def is_block_type(tinfo: tinfo_t) -> bool:
    """Check if the type is an Obj-C block type"""
    if not tinfo.is_struct():
        return False
    # noinspection PyTypeChecker
    name: str | None = tinfo.get_type_name()
    return name is not None and name.startswith(IDA_BLOCK_TYPE_NAME_PREFIX)


def block_member_is_arg_field(udm: udm_t) -> bool:
    """Check if the member is an argument field of an Obj-C block"""
    return udm.name not in IDA_BLOCK_TYPE_BASE_FIELD_NAMES
