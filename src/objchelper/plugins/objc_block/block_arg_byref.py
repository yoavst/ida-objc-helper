__all__ = ["BlockArgByRefField", "create_block_arg_byref_type", "is_block_arg_byref_type"]

from enum import Enum

from ida_typeinf import tinfo_t

from objchelper.idahelper import tif

PTR_SIZE = 8
INT_SIZE = 4

OFFSET_ISA = 0
OFFSET_FORWARDING = OFFSET_ISA + PTR_SIZE
OFFSET_FLAGS = OFFSET_FORWARDING + PTR_SIZE
OFFSET_SIZE = OFFSET_FLAGS + INT_SIZE
OFFSET_BYREF_KEEP = OFFSET_SIZE + INT_SIZE
OFFSET_BYREF_DISPOSE = OFFSET_BYREF_KEEP + PTR_SIZE
OFFSETS = [OFFSET_ISA, OFFSET_FORWARDING, OFFSET_FLAGS, OFFSET_SIZE, OFFSET_BYREF_KEEP, OFFSET_BYREF_DISPOSE]


class BlockArgByRefField(Enum):
    """
    struct _block_byref_x {
        void *isa;
        struct _block_byref_x *forwarding;
        int flags;
        int size;
        /* optional */ void (*byref_keep)(void  *dst, void *src);
        /* optional */ void (*byref_dispose)(void *);
        typeof(marked_variable) marked_variable;
    };
    """

    ISA = 0
    FORWARDING = 1
    FLAGS = 2
    SIZE = 3
    HELPER_KEEP = 4
    HELPER_DISPOSE = 5
    VARIABLE = 6

    def get_offset(self, has_helpers: bool | None = None) -> int:
        if self == BlockArgByRefField.VARIABLE and has_helpers is None:
            raise ValueError("has_helpers must be specified for VARIABLE")  # noqa: TRY003

        if self == BlockArgByRefField.VARIABLE:
            return OFFSET_BYREF_DISPOSE + PTR_SIZE if has_helpers else OFFSET_BYREF_KEEP

        return OFFSETS[self.value]


TYPE_BLOCK_ARG_BYREF_PREFIX = "Block_byref_layout_"
TYPE_DECL_BLOCK_ARG_BYREF_WITH_HELPERS = """
#pragma pack(push, 1)
struct {class_name} {{
    void *isa;
    struct {class_name} *forwarding;
    int flags;
    int size;
    void (*byref_keep)(void  *dst, void *src);
    void (*byref_dispose)(void *);
    {var_type} value;
}};
#pragma pack(pop)
"""
TYPE_DECL_BLOCK_ARG_BYREF_WITHOUT_HELPERS = """
#pragma pack(push, 1)
struct {class_name} {{
    void *isa;
    struct {class_name} *forwarding;
    int flags;
    int size;
    {var_type} value;
}};
#pragma pack(pop)
"""


def get_type_name_for_addr(ea: int) -> str:
    return f"{TYPE_BLOCK_ARG_BYREF_PREFIX}{ea:08X}"


def is_block_arg_byref_type(tinfo: tinfo_t) -> bool:
    """Check if the given `tif` is a block arg byref type"""
    if not tinfo.is_struct():
        return False
    name: str | None = tinfo.get_type_name()
    return name is not None and name.startswith(TYPE_BLOCK_ARG_BYREF_PREFIX)


def create_block_arg_byref_type(ea: int, var_size: int, has_helpers: bool) -> tinfo_t:
    """Create a tinfo_t for the block byref type"""
    class_name = get_type_name_for_addr(ea)

    if (existing_type := tif.from_struct_name(class_name)) is not None:
        return existing_type

    var_type = tif.from_size(var_size).dstr()
    if has_helpers:
        type_decl = TYPE_DECL_BLOCK_ARG_BYREF_WITH_HELPERS.format(class_name=class_name, var_type=var_type)
    else:
        type_decl = TYPE_DECL_BLOCK_ARG_BYREF_WITHOUT_HELPERS.format(class_name=class_name, var_type=var_type)

    tif.create_from_c_decl(type_decl)
    return tif.from_struct_name(class_name)
