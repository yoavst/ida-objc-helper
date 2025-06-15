import idaapi
from ida_funcs import func_t
from ida_hexrays import cfunc_t, lvar_t, lvars_t


def from_ea(ea: int) -> cfunc_t | None:
    f = idaapi.get_func(ea)
    if f is None:
        return None

    return from_func(f)


def from_func(func: func_t) -> cfunc_t | None:
    decompiled = idaapi.decompile(func)
    if decompiled is None:
        return None
    # It actually returns `cfuncptr_t` but for the sake of simplicity let's lie
    # noinspection PyTypeChecker
    return decompiled  # type: ignore  # noqa: PGH003


def get_lvar_by_offset(func: cfunc_t, offset: int) -> lvar_t:
    lvars: lvars_t = func.get_lvars()
    for lv in lvars:
        if lv.get_stkoff() == offset:
            return lv
