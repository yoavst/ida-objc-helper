import ida_bytes
import idaapi
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


def ea_from_name(name: str) -> int | None:
    """Given a name return the EA of the symbol"""
    ea = idc.get_name_ea(idaapi.BADADDR, name)
    if ea == idaapi.BADADDR:
        return None
    return ea
