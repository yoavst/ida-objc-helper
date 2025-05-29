import idaapi


def get_start_of_function(ea: int) -> int | None:
    """Get the beginning of the function the given address is in."""
    func = idaapi.get_func(ea)
    if func is None:
        return None
    return func.start_ea


def is_in_function(ea: int) -> bool:
    """Check if the given address is in a function."""
    return idaapi.get_func(ea) is not None
