__all__ = ["main"]

import ida_hexrays
import idc
from ida_hexrays import lvar_t, mblock_t, minsn_t, mop_t

from objchelper.idahelper import pac
from objchelper.idahelper.microcode import mba, mop
from objchelper.idahelper.microcode.visitors import extended_microcode_visitor_t


def main():
    # Check pac xrefs works
    print(list(map(hex, pac.pac_xrefs_to_func(0xFFFFFFF009A77B10))))
    print(list(map(hex, pac.pac_candidates_for_call(0xFFFFFFF009A77ACC))))

    # func_mba = mba.from_func(0xFFFFFFF009A77A5C)
    # func_mba = mba.from_func(0xFFFFFFF00879AEA8)
    func_mba = mba.from_func(idc.here())
    ret_lvar = mba.get_ret_lvar(func_mba)
    print(ret_lvar.name)
    mreg_ret_lvar = ret_lvar.get_reg1() if ret_lvar is not None else None

    # ret_lvar_mop = mop.from_lvar(ret_lvar, func_mba)
    #
    # ret_lvar_mop_2 = list(mba.blocks(func_mba))[4].tail.d

    for i, block in enumerate(mba.blocks(func_mba)):
        print(f"Block {i} at {block.start:#X} - {block.end:#X}")
        # if not block_define_mreg_fast(block, mreg_ret_lvar):
        #     continue

        visitor = lvar_assignment_visitor_t(ret_lvar)
        visitor.visit_block(block)
        if visitor.results:
            lvar_assignment_results(visitor.results)
        # for j, ins in enumerate(mblock.instructions(block)):
        # print(f"\t{j} - {ins.dstr()}")
        # # Search for instructions that modify variables
        # if not ins.modifies_d():
        #     continue
        # d_mop: mop_t = ins.d
        # print("d:", d_mop.dstr())

        # # print('must be use:', block.mustbuse.dstr())
        # # print('may be use:', block.maybuse.dstr())
        # print('must be def:', block.mustbdef.dstr())
        # # print('may be def:', block.maybdef.dstr())
        #
        # l: rlist_t = block.mustbdef.reg.dstr()
        # for i in l:
        #     print(i)

        # for j, ins in enumerate(mblock.instructions(block)):
        #     print(f"\t{ins.ea:#X} - {ins.dstr()}")


def lvar_assignment_results(results: list[tuple[mop_t, list[mop_t | minsn_t]]]) -> None:
    for op, parents in results:
        print(f"Found lvar: {op.dstr()}")
        print(f"Parents: {', '.join([p.dstr() for p in parents])}")

        # Mop can be a child of the following:
        # - direction instruction operand (l,r,d)
        # - function argument
        # - ref to a variable
        # - pair but pasten

        parent = parents[-1]
        if isinstance(parent, minsn_t):
            if parent.d == op:
                # TODO support all
                print('Found my var as a destination of an instruction!')
                if parent.is_like_move():
                    print('Found my var as a move instruction!')

        else:
            if parent.t == ida_hexrays.mop_f:
                print('Found my var as a function argument! so ignored')
            else:
                assert parent.t == ida_hexrays.mop_a
                print('Found my var inside a reference!')


class lvar_assignment_visitor_t(extended_microcode_visitor_t):
    def __init__(self, lvar: lvar_t):
        super().__init__()
        self.lvar = lvar
        self.results: list[tuple[mop_t, list[mop_t | minsn_t]]] = []

    def _visit_mop(self, op: mop_t) -> int:
        # print('  ' * len(self.parents), "MOP:", op.dstr())

        mop_lvar = mop.get_local_variable(op)
        if mop_lvar is None:
            return 0

        if mop_lvar == self.lvar:
            self.results.append((op, self.parents[:]))

        return 0

    def _visit_insn(self, ins: minsn_t) -> int:
        # print('  ' * len(self.parents), "INS:", ins.dstr())
        return 0


def block_define_mreg_fast(block: mblock_t, mreg: int) -> bool:
    """Check if a block might define a mreg."""
    return block.mustbdef.has(mreg) or block.maybdef.has(mreg)
