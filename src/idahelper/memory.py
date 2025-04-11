import idc


def str_from_ea(ea: int) -> str:
    """Given EA return as string the C-String stored at that location"""
    return idc.get_strlit_contents(ea).decode()
