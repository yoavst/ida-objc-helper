import idaapi
import idc
from ida_typeinf import tinfo_t


def demangle(symbol: str, strict: bool = False) -> str | None:
    """Demangle cpp symbol."""
    res = idc.demangle_name(symbol, idc.get_inf_attr(idc.INF_SHORT_DEMNAMES))
    if strict:
        return res
    return res or symbol


def demangle_name_only(symbol: str, strict: bool = False) -> str | None:
    """Demangle cpp symbol, return name of the function (including class)"""
    res = demangle(symbol, strict)
    if res is not None:
        return res.split("(")[0]
    return None


def demangle_class_only(symbol: str, strict: bool = False) -> str | None:
    """Demangle cpp symbol, return name of the class"""
    name = demangle_name_only(symbol, strict)
    if name is None:
        return None
    # Expected Class::methodName or Class::innerClass::methodName
    last_double_colon = name.rfind("::")
    if last_double_colon == -1:
        return None
    return name[:last_double_colon]


def vtable_location_from_type(cpp_type: tinfo_t) -> int | None:
    """Find the location of the "`vtable'TYPE" for the given `cpp_type`"""
    # noinspection PyTypeChecker
    type_name: str = cpp_type.get_type_name()
    ea = idc.get_name_ea(idaapi.BADADDR, f"__ZTV{len(type_name)}{type_name}")
    return ea if ea != idaapi.BADADDR else None
