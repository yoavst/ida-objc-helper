from typing import Protocol

import ida_hexrays
import ida_idaapi
import idaapi
from ida_idaapi import plugin_t
from ida_kernwin import action_handler_t

from plugins.objc_refcnt import optimizer as objc_optimizer
from plugins.oslog import optimizers as oslog_optimizers

TOGGLE_ACTION_ID = "objchelper:toggle"


class Optimizer(Protocol):
    def install(self) -> None: ...

    def remove(self) -> bool: ...


class ObjcHelperPlugin(plugin_t):
    flags = ida_idaapi.PLUGIN_HIDE
    wanted_name = "Obj-C helper"
    wanted_hotkey = ""
    comment = "Optimize Objective-C patterns in the code"
    help = ""

    optimizers: list[Optimizer]
    is_enabled: bool = True

    def init(self) -> int:
        print("[ObjcOptimizer] init")
        if ida_hexrays.init_hexrays_plugin() and self.register_actions():
            self.optimizers = [objc_optimizer(), *[opt() for opt in oslog_optimizers]]
            self.install()
            return ida_idaapi.PLUGIN_KEEP
        else:
            return ida_idaapi.PLUGIN_SKIP

    def install(self) -> None:
        self.is_enabled = True
        for optimizer in self.optimizers:
            optimizer.install()

    def remove(self) -> None:
        self.is_enabled = False
        for optimizer in self.optimizers:
            optimizer.remove()

    def register_actions(self) -> bool:
        if not idaapi.register_action(
            idaapi.action_desc_t(
                TOGGLE_ACTION_ID,  # Must be the unique item
                "Toggle Obj-C helper optimizations",  # The name the user sees
                ObjcHelperToggleActionHandler(self),  # The function to call
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

    def term(self) -> None:
        self.remove()
        idaapi.unregister_action(TOGGLE_ACTION_ID)


class ObjcHelperToggleActionHandler(action_handler_t):
    def __init__(self, plugin: ObjcHelperPlugin):
        super().__init__()
        self.plugin = plugin

    def activate(self, ctx):
        if self.plugin.is_enabled:
            self.plugin.remove()
        else:
            self.plugin.install()

        print("Obj-C optimization are now:", "enabled" if self.plugin.is_enabled else "disabled")
        print("Note: You might need to perform decompile again for this change to take effect.")
        return 1

    def update(self, ctx) -> int:
        return idaapi.AST_ENABLE_ALWAYS


# noinspection PyPep8Naming
def PLUGIN_ENTRY() -> plugin_t:
    return ObjcHelperPlugin()
