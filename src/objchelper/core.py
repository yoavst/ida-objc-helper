__all__ = ["plugin_core"]

import ida_kernwin
import idaapi

from .base.reloadable_plugin import Component, PluginCore
from .idahelper import widgets
from .plugins.objc_refcnt import component as objc_refcount_component
from .plugins.oslog import component as oslog_component

TOGGLE_ACTION_ID = "objchelper:toggle"


class UIActionsComponent(Component):
    def __init__(self, core: "PluginCore"):
        super().__init__("ui actions", core)

    def load(self) -> bool:
        if not idaapi.register_action(
            idaapi.action_desc_t(
                TOGGLE_ACTION_ID,  # Must be the unique item
                "Toggle Obj-C helper optimizations",  # The name the user sees
                ObjcHelperToggleActionHandler(self.core),  # The function to call
            )
        ):
            print("[Error] Failed to register action")
            return False

        if not idaapi.attach_action_to_menu(
            "Edit/Other/...",  # The menu location
            TOGGLE_ACTION_ID,  # The unique function ID
            0,
        ):
            print("[Error] Failed to attach to menu")
            return False
        return True

    def unload(self):
        idaapi.unregister_action(TOGGLE_ACTION_ID)


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


plugin_core = PluginCore.factory("ObjcHelper", [objc_refcount_component, oslog_component, UIActionsComponent])
