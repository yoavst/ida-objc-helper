import ida_bytes
import idaapi
import idc

RETRY_COUNT = 20


def str_from_ea(ea: int) -> str | None:
    """Given EA return as string the C-String stored at that location"""
    content = idc.get_strlit_contents(ea)
    if content is None:
        return None
    return content.decode()


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


def set_name(ea: int, name: str, retry: bool = False) -> bool:
    """Set the name of the symbol at EA to the given name"""
    res = bool(idc.set_name(ea, name, idc.SN_NOWARN | idc.SN_AUTO))
    if res or not retry:
        return res

    print(f"Failed to set name {name} at {hex(ea)}, retrying with postfix")
    for i in range(1, RETRY_COUNT + 1):
        new_name = f"{name}_{i}"
        res = bool(idc.set_name(ea, new_name, idc.SN_NOWARN | idc.SN_AUTO))
        if res:
            return res


def is_user_defined_name(ea: int) -> bool:
    """Check if the name at EA is user defined"""
    ea_flags = ida_bytes.get_full_flags(ea)
    if ea_flags == 0:
        print("[Error] EA is not valid")
        return False

    return ida_bytes.has_user_name(ea_flags)
