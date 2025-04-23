import idc


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
