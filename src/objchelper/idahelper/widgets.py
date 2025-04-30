import ida_hexrays
import ida_kernwin
import idaapi
from ida_hexrays import citem_t
from ida_kernwin import Choose


def refresh_pseudocode_widgets() -> None:
    """Refresh all pseudocode widgets in IDA Pro, forcing redecompiling."""
    for name in "ABCDEFGHIJKLMNOPQRSTUVWXY":
        widget = idaapi.find_widget(f"Pseudocode-{name}")
        if widget is not None:
            refresh_widget(widget)


def refresh_widget(widget: "TWidget *") -> None:  # noqa: F722
    """Refresh a given widget."""
    vdui: idaapi.vdui_t = idaapi.get_widget_vdui(widget)
    if vdui is None:
        return
    vdui.refresh_view(True)


def get_current_citem() -> citem_t | None:
    """Get the current citem in the active pseudocode window."""
    w = ida_kernwin.get_current_widget()
    if ida_kernwin.get_widget_type(w) != ida_kernwin.BWN_PSEUDOCODE:
        return None

    vu = ida_hexrays.get_widget_vdui(w)
    if vu is None:
        return None

    if not vu.get_current_item(ida_hexrays.USE_KEYBOARD) or not vu.item.is_citem():
        return None

    return vu.item.e


def jump_to(ea: int) -> None:
    """Jump to a given address in the current view."""
    ida_kernwin.jumpto(ea)


class EAChoose(Choose):
    """A chooser for data of the type <ea>:<description>"""

    def __init__(
        self,
        title: str,
        items: list[tuple[int, str]],
        col_names: tuple[str, str] = ("Address", "Name"),
        flags: int = 0,
        modal=False,
        embedded: bool = False,
        width: int | None = None,
        height: int | None = None,
    ):
        Choose.__init__(
            self,
            title,
            [[col_names[0], 10 | Choose.CHCOL_EA], [col_names[1], 40 | Choose.CHCOL_FNAME]],
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
