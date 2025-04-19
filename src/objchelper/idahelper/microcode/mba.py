from collections.abc import Iterator

from ida_hexrays import mba_t, mblock_t


def blocks(mba: mba_t) -> Iterator[mblock_t]:
    """Create a generator of the block's instructions"""
    for i in range(mba.qty):
        yield mba.get_mblock(i)
