from collections.abc import Iterator

from ida_hexrays import mblock_t, minsn_t


def instructions(blk: mblock_t) -> Iterator[minsn_t]:
    """Create a generator of the block's instructions"""
    ins: minsn_t = blk.head
    while ins is not None:
        yield ins
        ins = ins.next
