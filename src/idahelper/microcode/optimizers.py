from asyncio import Protocol
from collections.abc import Callable

from ida_hexrays import mblock_t, minsn_t, optblock_t, optinsn_t

from base.utils import CounterMixin


class optblock_counter_t(optblock_t, CounterMixin, Protocol): ...


class optinsn_counter_t(optinsn_t, CounterMixin, Protocol): ...


class optblock_counter_wrapper_t(optblock_t):
    def __init__(self, factory: Callable[[], optblock_counter_t]):
        super().__init__()
        self.factory = factory

    def func(self, blk: mblock_t) -> int:
        optimizer = self.factory()
        optimizer.func(blk)
        return optimizer.cnt


class optinsn_counter_wrapper_t(optinsn_t):
    def __init__(self, factory: Callable[[], optinsn_counter_t]):
        super().__init__()
        self.factory = factory

    def func(self, blk: mblock_t, ins: minsn_t, optflags: int) -> int:
        optimizer = self.factory()
        optimizer.func(blk, ins, optflags)
        return optimizer.cnt
