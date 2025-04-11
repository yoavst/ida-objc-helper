import dataclasses

import ida_hexrays
import ida_typeinf
from ida_typeinf import tinfo_t


def from_c_type(c_type: str) -> tinfo_t | None:
    """Given a C type string, return matching `tinfo_t`"""
    tif = tinfo_t()
    if c_type == "void":
        tif.create_simple_type(ida_typeinf.BT_VOID)
        return tif
    else:
        # noinspection PyTypeChecker
        if (
            ida_typeinf.parse_decl(
                tif,
                None,
                c_type + ";",
                ida_typeinf.PT_SIL | ida_typeinf.PT_NDC | ida_typeinf.PT_TYP,
            )
            is not None
        ):
            return tif
    return None


def from_size(size: int) -> tinfo_t | None:
    """Convert number of bytes to `tinfo_t`"""
    # Using those types seems to make IDA hide casts
    if size == 1:
        return tinfo_t(ida_typeinf.BT_UNK_BYTE)
    elif size == 2:
        return tinfo_t(ida_typeinf.BT_UNK_WORD)
    elif size == 4:
        return tinfo_t(ida_typeinf.BT_UNK_DWORD)
    elif size == 8:
        return tinfo_t(ida_typeinf.BT_UNK_QWORD)
    else:
        print(f"[Error] unsupported size {size}")
        return None


@dataclasses.dataclass
class FuncParam:
    type: str
    name: str | None = None


def from_func(return_type: str, parameters: list[FuncParam]) -> tinfo_t | None:
    """Create a tif from return type and list of parameters"""
    params_str = ",".join(f"{p.type} {p.name or ''}" for p in parameters)
    sig = f"{return_type} f({params_str})"
    return from_c_type(sig)


def pointer_of(tif: tinfo_t) -> tinfo_t:
    """Given a tif, return tif of pointer to the type"""
    return ida_hexrays.make_pointer(tif)
