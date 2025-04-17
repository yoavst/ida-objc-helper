import idc


def demangle(symbol: str) -> str | None:
    """Demangle cpp symbol."""
    return idc.demangle_name(symbol, idc.get_inf_attr(idc.INF_SHORT_DEMNAMES))


def demangle_name_only(symbol: str) -> str | None:
    """Demangle cpp symbol."""
    res = idc.demangle_name(symbol, idc.get_inf_attr(idc.INF_SHORT_DEMNAMES))
    if res is not None:
        return res.split('(')[0]
    return None
