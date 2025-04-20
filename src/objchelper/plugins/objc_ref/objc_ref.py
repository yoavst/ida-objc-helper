__all__ = ["locate_selector_xrefs"]

import ida_kernwin
import idautils
import idc
from ida_kernwin import Choose


class XrefsChoose(Choose):
    def __init__(
        self,
        selector: str,
        items: list[tuple[int, str]],
        flags: int = 0,
        modal=False,
        embedded: bool = False,
        width: int | None = None,
        height: int | None = None,
    ):
        Choose.__init__(
            self,
            f"Xrefs to selector: {selector}",
            [["Address", 10 | Choose.CHCOL_EA], ["Name", 40 | Choose.CHCOL_FNAME]],
            flags=flags | Choose.CH_RESTORE,
            embedded=embedded,
            width=width,
            height=height,
        )
        self.items = items
        self.modal = modal

    def OnInit(self):
        return True

    def OnGetSize(self):
        return len(self.items)

    def OnGetLine(self, n):
        ea, name = self.items[n]
        return hex(ea), name

    def OnGetEA(self, n):
        return self.items[n][0]

    def OnSelectLine(self, n):
        ea = int(self.items[n][0])
        ida_kernwin.jumpto(ea)
        return (Choose.NOTHING_CHANGED,)

    def show(self):
        ok = self.Show(self.modal) >= 0
        return ok


# Taken from: https://github.com/doronz88/ida-scripts/blob/main/objc_hotkeys.py
IGNORED_SECTIONS = ("__objc_const",)


def get_name_for_ea(ea: int) -> str:
    func_name = idc.get_func_name(ea)
    func_address = idc.get_name_ea_simple(func_name)
    return func_name if ea == func_address else f"{func_name}+{ea - func_address:08x}"


def locate_selector_xrefs() -> None:
    current_ea = idc.get_screen_ea()
    func_name = idc.get_func_name(current_ea)
    try:
        selector = func_name.split(" ")[1].split("]")[0]
    except IndexError:
        print("Failed to find current selector")
        return
    print(f"looking for references to: {selector}")

    items = [
        (ea.frm, get_name_for_ea(ea.frm))
        for ea in idautils.XrefsTo(idc.get_name_ea_simple(f"_objc_msgSend${selector}"))
    ]
    if items:
        for ea, name in items:
            print(f"0x{ea:08x} {name}")
        xrefs_choose = XrefsChoose(selector, items, modal=True)
        xrefs_choose.show()
