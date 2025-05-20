import dataclasses
from collections.abc import Callable, Iterable
from enum import Enum, auto

from ida_hexrays import minsn_t, mop_t

# Backward - what could be the value of the variable
# Forward - who uses the variable

class Op(Enum):
    BACKWARD_ASSIGN = auto()
    FORWARD_ASSIGN = auto()
    REF = auto()
    DEREF = auto()


class TypeModifier(Enum):
    """T -> T*"""
    REF = auto()
    """T* -> T"""
    DEREF = auto()
    """T* -> __shifted(T, <offset>), Pointer to field (in the given offset) of the object"""
    SHIFT = auto()
    """T* -> __shifted(T, <unknown>), a pointer to unknown field in the object"""
    UNKNOWN_SHIFT = auto()
    """F(X1, X2, ...): Y -> Y"""
    CALL = auto()


Mission = Callable[["MissionContext"], Iterable[tuple["MissionContext", "Mission"]]]


@dataclasses.dataclass
class MissionContext:
    type_modifiers: list[TypeModifier]
    history: list[tuple[Op, mop_t | minsn_t]]
    callback_mission: Mission

