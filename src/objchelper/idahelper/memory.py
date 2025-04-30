import ida_bytes
import idc


def str_from_ea(ea: int) -> str:
    """Given EA return as string the C-String stored at that location"""
    return idc.get_strlit_contents(ea).decode()


def name_from_ea(ea: int) -> str | None:
    """Given EA return the name of the symbol"""
    return idc.get_name(ea)


def qword_from_ea(ea: int) -> int:
    """Given EA return the 8 byte value stored at that location"""
    return ida_bytes.get_qword(ea)
