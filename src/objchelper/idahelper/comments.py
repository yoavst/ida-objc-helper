import ida_bytes
from ida_hexrays import ITP_COLON, ITP_SEMI, cfunc_t, treeloc_t


def get_asm_comment(ea: int, repeatable: bool = False) -> str | None:
    """Get the comment of the given ea or none if it has no comment"""
    return ida_bytes.get_cmt(ea, repeatable)


def set_asm_comment(ea: int, comment: str, repeatable: bool = False) -> bool:
    """Set the comment for the given ea"""
    return ida_bytes.set_cmt(ea, comment, repeatable)


def set_psuedocode_comment(address: int, cfunc: cfunc_t, comment: str) -> bool:
    """Try to set comment in psuedocode"""
    eamap = cfunc.get_eamap()
    obj_addr = eamap[address][0].ea

    # get a ctree location object to place a comment there
    tl = treeloc_t()
    tl.ea = obj_addr

    # since the public documentation on IDAs APIs is crap and I don't know any other way, we have to brute force the item preciser
    # we do this by setting the comments with different idaapi.ITP_* types until our comment does not create an orphaned comment
    for itp in range(ITP_SEMI, ITP_COLON):
        tl.itp = itp
        cfunc.set_user_cmt(tl, comment)
        cfunc.save_user_cmts()
        # # apparently you have to cast cfunc to a string, to make it update itself
        cfunc.__str__()
        if not cfunc.has_orphan_cmts():
            cfunc.save_user_cmts()
            return True
        cfunc.del_orphan_cmts()
    return False
