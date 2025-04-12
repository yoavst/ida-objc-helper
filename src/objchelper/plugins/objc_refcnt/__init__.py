__all__ = ["component"]

from ...base.reloadable_plugin import OptimizersComponent
from .optimizer import objc_calls_optimizer_t as optimizer

component = OptimizersComponent.factory("Obj-C refcount optimizer", [optimizer])
