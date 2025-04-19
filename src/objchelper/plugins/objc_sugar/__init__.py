__all__ = ["objc_sugar_component"]

from objchelper.base.reloadable_plugin import HexraysHookComponent
from objchelper.plugins.objc_sugar.objc_sugar import objc_selector_hexrays_hooks_t

objc_sugar_component = HexraysHookComponent.factory("ObjcSugar", [objc_selector_hexrays_hooks_t])
