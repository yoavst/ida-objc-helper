import dataclasses

import ida_hexrays
import ida_typeinf
import idaapi
from ida_funcs import func_t
from ida_typeinf import func_type_data_t, tinfo_t, udm_t, udt_type_data_t


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
    if not tif.get_named_type(ida_typeinf.get_idati(), name, ida_typeinf.BTF_TYPEDEF, True, False):
        return None
    return tif


def from_func(func: func_t) -> tinfo_t | None:
    """Given a function, return matching `tinfo_t`"""
    tif = tinfo_t()
    if idaapi.get_tinfo(tif, func.start_ea):
        return tif


def get_func_details(func: func_t | tinfo_t) -> func_type_data_t | None:
    """Given a function, return its type details"""
    # Convert to tif
    if isinstance(func, func_t):
        func = from_func(func)
        if func is None:
            return None

    func_type = func_type_data_t()
    if func.get_func_details(func_type):
        return func_type


def from_func_details(details: func_type_data_t) -> tinfo_t | None:
    """Given a function type details, return matching `tinfo_t`"""
    tif = tinfo_t()
    if tif.create_func(details):
        return tif


def apply_tinfo(tif: tinfo_t, func: func_t) -> bool:
    """Apply typing info to the given function`"""
    return idaapi.apply_tinfo(func.start_ea, tif, idaapi.TINFO_DEFINITE)


@dataclasses.dataclass
class FuncParam:
    type: str
    name: str | None = None


def from_func_components(return_type: str, parameters: list[FuncParam]) -> tinfo_t | None:
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


def set_udm_type(tif: tinfo_t, udm: udm_t, udm_type: tinfo_t) -> bool:
    """For a `udm` of a `tif`, set its type"""
    index = tif.find_udm(udm, ida_typeinf.STRMEM_OFFSET)
    if index == -1:
        return False

    return tif.set_udm_type(index, udm_type) == 0


def create_from_c_decl(decl: str) -> bool:
    """Create a new type definition from `decl`"""
    return not ida_typeinf.idc_parse_types(decl, 0)
