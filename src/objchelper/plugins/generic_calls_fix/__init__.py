__all__ = ["generic_calls_fix_component"]

from objchelper.base.reloadable_plugin import OptimizersComponent
from objchelper.plugins.generic_calls_fix.generic_calls_fix import generic_calls_fix_optimizer_t

generic_calls_fix_component = OptimizersComponent.factory("Generic calls fixer", [generic_calls_fix_optimizer_t])
