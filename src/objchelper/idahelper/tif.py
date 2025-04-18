import dataclasses

import ida_hexrays
import ida_typeinf
from ida_typeinf import tinfo_t, udm_t, udt_type_data_t


def from_c_type(c_type: str) -> tinfo_t | None:
    """Given a C type string, return matching `tinfo_t`"""
    tif = tinfo_t()
    if c_type == "void":
        tif.create_simple_type(ida_typeinf.BT_VOID)
        return tif
    else:
        # noinspection PyTypeChecker
        if (
            ida_typeinf.parse_decl(
                tif,
                None,
                c_type + ";",
                ida_typeinf.PT_SIL | ida_typeinf.PT_NDC | ida_typeinf.PT_TYP,
            )
            is not None
        ):
            return tif
    return None


def from_size(size: int) -> tinfo_t | None:
    """Convert number of bytes to `tinfo_t`"""
    # Using those types seems to make IDA hide casts
    if size == 1:
        return tinfo_t(ida_typeinf.BT_UNK_BYTE)
    elif size == 2:
        return tinfo_t(ida_typeinf.BT_UNK_WORD)
    elif size == 4:
        return tinfo_t(ida_typeinf.BT_UNK_DWORD)
    elif size == 8:
        return tinfo_t(ida_typeinf.BT_UNK_QWORD)
    else:
        print(f"[Error] unsupported size {size}")
        return None


def from_struct_name(name: str) -> tinfo_t | None:
    """Given a struct name, return matching `tinfo_t`"""
    tif = tinfo_t()
    if not tif.get_named_type(ida_typeinf.get_idati(), name, ida_typeinf.BTF_STRUCT, True, False):
        return None
    return tif


@dataclasses.dataclass
class FuncParam:
    type: str
    name: str | None = None


def from_func(return_type: str, parameters: list[FuncParam]) -> tinfo_t | None:
    """Create a tif from return type and list of parameters"""
    params_str = ",".join(f"{p.type} {p.name or ''}" for p in parameters)
    sig = f"{return_type} f({params_str})"
    return from_c_type(sig)


def pointer_of(tif: tinfo_t) -> tinfo_t:
    """Given a tif, return tif of pointer to the type"""
    return ida_hexrays.make_pointer(tif)


def get_member(tif: tinfo_t, offset: int) -> udm_t | None:
    """Get member of a struct at given offset"""
    if not tif.is_struct():
        print("Not a struct type!")
        return None

    udt_data = udt_type_data_t()
    if not tif.get_udt_details(udt_data):
        return None

    udm = udm_t()
    udm.offset = offset * 8
    if tif.find_udm(udm, ida_typeinf.STRMEM_OFFSET) == -1:
        return None

    return udm


def create_from_c_decl(decl: str) -> bool:
    """Create a new type definition from `decl`"""
    return not ida_typeinf.idc_parse_types(decl, 0)
