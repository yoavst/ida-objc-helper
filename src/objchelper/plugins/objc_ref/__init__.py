__all__ = ["objc_xrefs_component"]

import ida_kernwin
import idaapi

from objchelper.base.reloadable_plugin import UIAction, UIActionsComponent
from objchelper.plugins.objc_ref.objc_ref import locate_selector_xrefs

ACTION_ID = "objchelper:show_objc_xrefs"

objc_xrefs_component = UIActionsComponent.factory(
    "Show objc xrefs",
    [
        lambda core: UIAction(
            ACTION_ID,
            idaapi.action_desc_t(
                ACTION_ID, "Show xrefs for current Obj-C method's selector", ObjcHelperToggleActionHandler(), "Ctrl+4"
            ),
        )
    ],
)


class ObjcHelperToggleActionHandler(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        locate_selector_xrefs()
        return 0

    def update(self, ctx) -> int:
        return idaapi.AST_ENABLE_ALWAYS
