import ida_idaapi
from ida_idaapi import plugin_t

from objchelper.base.reloadable_plugin import ReloadablePlugin
from objchelper.core import plugin_core


class ObjcHelperPlugin(ReloadablePlugin):
    flags = ida_idaapi.PLUGIN_HIDE
    wanted_name = "Obj-C helper"
    wanted_hotkey = ""
    comment = "Optimize Objective-C patterns in the code"
    help = ""

    def __init__(self):
        super().__init__("objchelper", "objchelper", plugin_core)


# noinspection PyPep8Naming
def PLUGIN_ENTRY() -> plugin_t:
    return ObjcHelperPlugin()
