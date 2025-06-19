from collections.abc import Iterator

import ida_funcs
import ida_ida
import idaapi
from ida_funcs import func_t

FLAG_NO_RETURN = ida_funcs.FUNC_NORET
FLAG_OUTLINE = ida_funcs.FUNC_OUTLINE


def iterate_functions(start: int | None = None, end: int | None = None) -> Iterator[func_t]:
    """Iterate all the function in the given range or the whole project"""
    # Copied from idautils.functions
    if start is None:
        start = ida_ida.inf_get_min_ea()
    if end is None:
        end = ida_ida.inf_get_max_ea()

    chunk = ida_funcs.get_fchunk(start)
    if not chunk:
        chunk = ida_funcs.get_next_fchunk(start)
    while chunk and chunk.start_ea < end and (chunk.flags & ida_funcs.FUNC_TAIL) != 0:
        chunk = ida_funcs.get_next_fchunk(chunk.start_ea)
    func = chunk

    while func and func.start_ea < end:
        startea = func.start_ea
        yield func
        func = ida_funcs.get_next_func(startea)


def get_start_of_function(ea: int) -> int | None:
    """Get the beginning of the function the given address is in."""
    func = idaapi.get_func(ea)
    if func is None:
        return None
    return func.start_ea


def is_in_function(ea: int) -> bool:
    """Check if the given address is in a function."""
    return idaapi.get_func(ea) is not None


def add_function(start_ea: int, end_ea: int) -> bool:
    """Add a function with the given start and end addresses and name."""
    return idaapi.add_func(start_ea, end_ea)


def has_flags(func: int | func_t, flag: int) -> bool:
    """Check if function already has the given flag"""
    _func = idaapi.get_func(func) if isinstance(func, int) else func

    if _func is None:
        return False

    return _func.flags & flag == flag


def apply_flag_to_function(func: int | func_t, flag: int) -> bool:
    """Apply a flag to the function at the given address."""
    _func = idaapi.get_func(func) if isinstance(func, int) else func
    if _func is None:
        return False

    _func.flags |= flag
    return ida_funcs.update_func(_func)


def remove_flag_to_function(func: int | func_t, flag: int) -> bool:
    """Remove a flag from a function at the given address."""
    _func = idaapi.get_func(func) if isinstance(func, int) else func
    if _func is None:
        return False

    _func.flags &= ~flag
    return ida_funcs.update_func(_func)


def get_next_function(func: int | func_t) -> func_t | None:
    """Given a function, return the next function in the binary"""
    ea = func.start_ea if isinstance(func, func_t) else func
    return ida_funcs.get_next_func(ea)
