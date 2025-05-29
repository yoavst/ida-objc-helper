import ida_funcs
import idaapi

FLAG_NO_RETURN = ida_funcs.FUNC_NORET
FLAG_OUTLINE = ida_funcs.FUNC_OUTLINE


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


def apply_flag_to_function(func_ea: int, flag: int) -> bool:
    """Apply a flag to the function at the given address."""
    func = idaapi.get_func(func_ea)
    if func is None:
        return False

    if func:
        func.flags |= flag
        return ida_funcs.update_func(func)
