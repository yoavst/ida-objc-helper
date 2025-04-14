__all__ = ["ObjcSugarComponent"]

from objchelper.base.reloadable_plugin import Component, PluginCore
from objchelper.plugins.objc_sugar.objc_sugar import objc_selector_hexrays_hooks_t


class ObjcSugarComponent(Component):
    def __init__(self, core: PluginCore):
        super().__init__("ObjcSugar", core)
        self.hooks: objc_selector_hexrays_hooks_t | None = None

    def load(self):
        self.hooks = objc_selector_hexrays_hooks_t()
        return True

    def mount(self) -> bool:
        assert self.hooks is not None, "load() must be called before mount()"

        return self.hooks.hook()

    def unmount(self):
        if self.hooks is not None:
            self.hooks.unhook()

    def unload(self):
        self.hooks = None
