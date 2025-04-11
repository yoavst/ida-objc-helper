import sys
from typing import Protocol

import ida_idaapi
import idaapi
from ida_idaapi import plugin_t

import objchelper


class Optimizer(Protocol):
    def install(self) -> None: ...

    def remove(self) -> bool: ...


class ObjcHelperPlugin(plugin_t):
    flags = ida_idaapi.PLUGIN_HIDE
    wanted_name = "Obj-C helper"
    wanted_hotkey = ""
    comment = "Optimize Objective-C patterns in the code"
    help = ""

    core: objchelper.PluginCore

    def init(self) -> int:
        print("[ObjcOptimizer] init")
        self.core = objchelper.PluginCore(defer_load=True)
        # Provide access from ida python console
        sys.modules["__main__"].objcopt = self
        return ida_idaapi.PLUGIN_KEEP

    def term(self) -> None:
        self.core.unload()

    def reload(self):
        """Hot-reload the plugin core."""
        print("Reloading...")
        self.core.unload()
        modules_to_reload = [module_name for module_name in sys.modules if module_name.startswith("objchelper")]
        for module_name in modules_to_reload:
            idaapi.require(module_name)
        self.core = objchelper.PluginCore()


# noinspection PyPep8Naming
def PLUGIN_ENTRY() -> plugin_t:
    return ObjcHelperPlugin()
