__all__ = ["plugin_core"]

import ida_kernwin
import idaapi

from .base.reloadable_plugin import PluginCore, UIAction, UIActionsComponent
from .idahelper import widgets
from .plugins.objc_ref import objc_xrefs_component
from .plugins.objc_refcnt import component as objc_refcount_component
from .plugins.objc_selector import ObjcSelectorComponent
from .plugins.oslog import component as oslog_component

TOGGLE_ACTION_ID = "objchelper:toggle"

toggle_objc_helper_mount_component = UIActionsComponent.factory(
    "toggle plugin mounting",
    [
        lambda core: UIAction(
            TOGGLE_ACTION_ID,
            idaapi.action_desc_t(
                TOGGLE_ACTION_ID,
                "Toggle Obj-C helper optimizations",
                ObjcHelperToggleActionHandler(core),
            ),
            menu_location="Edit/Other/...",
        )
    ],
)


class ObjcHelperToggleActionHandler(ida_kernwin.action_handler_t):
    def __init__(self, core: PluginCore):
        super().__init__()
        self.core = core

    def activate(self, ctx):
        if self.core.mounted:
            self.core.unmount()
        else:
            self.core.mount()

        widgets.refresh_pseudocode_widgets()

        print("Obj-C optimization are now:", "enabled" if self.core.mounted else "disabled")
        print("Note: You might need to perform decompile again for this change to take effect.")
        return 1

    def update(self, ctx) -> int:
        return idaapi.AST_ENABLE_ALWAYS


plugin_core = PluginCore.factory(
    "ObjcHelper", [
        objc_refcount_component,
        oslog_component,
        toggle_objc_helper_mount_component,
        objc_xrefs_component,
        ObjcSelectorComponent
    ]
)
