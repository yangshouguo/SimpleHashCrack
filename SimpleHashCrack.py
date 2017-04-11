
import pyvex
import cle
from pyvex import stmt,expr
ld = cle.Loader("HelloWorld")

Not_handle_tag = ["Ist_IMark","Ist_AbiHint"]
var_allocate = {}
class SimpleHashCrash:
    def __init__(self , start_addr , checksum , leng):
        self.fun_addr = start_addr
        self.checksum = checksum
        self.length = leng
    def getIRSBfromBin(self,addr, data_len = 0x100):
        # print hex(addr)
        some_text_data =  "".join(ld.memory.read_bytes(addr, data_len))
        irsb = pyvex.IRSB(some_text_data, addr, ld.main_bin.arch)
        return irsb


    # --------------------main-----------------------
    def crask(self):
        addr = self.fun_addr
        addr_go =[]
        addr_not_go = []
        addr_not_go.append(addr)
        z3_expr = []
        IR_INIT = []
        IR_LOOP = []
        IR_END = []
        # find all blocks in hash function
        while (len(addr_not_go)):

            if addr_not_go[0] not in addr_go:
                irsb = self.getIRSBfromBin(addr_not_go[0])
                # print irsb.pp()
                tmp = []
                tmp = IR_INIT
                addr_go.append(addr_not_go[0])
                del addr_not_go[0]
                nextmove = irsb.constant_jump_targets
                if (len(nextmove) == 0):
                    tmp = IR_END
                for addr in  (nextmove):
                    # print hex(addr)
                    if addr not in addr_go:
                        addr_not_go.append(addr)
                    else:
                        tmp = IR_LOOP
                stm_used = irsb.stmts_used
                # irsb.pp()
                # sa = []
                # sa.append("IRSB {")
                # sa.append("   %s" % irsb.tyenv)
                # sa.append("")
                for i, s in enumerate(irsb.statements):
                    stmt_str = ''
                    if isinstance(s, stmt.Put):
                        stmt_str = s.__str__(
                            reg_name=irsb.arch.translate_register_name(s.offset, s.data.result_size(irsb.tyenv) / 8))
                    elif isinstance(s, stmt.WrTmp) and isinstance(s.data, expr.Get):
                        stmt_str = s.__str__(
                            reg_name=irsb.arch.translate_register_name(s.data.offset, s.data.result_size(irsb.tyenv) / 8))
                    elif isinstance(s, stmt.Exit):
                        stmt_str = s.__str__(reg_name=irsb.arch.translate_register_name(s.offsIP, irsb.arch.bits))
                    else:
                        stmt_str = s.__str__()
                    # sa.append("   %02d | %s" % (i, stmt_str))
                    tmp.append(stmt_str)
                    # print stmt_str
                # sa.append(
                #     "   NEXT: PUT(%s) = %s; %s" % (irsb.arch.translate_register_name(irsb.offsIP), irsb.next, irsb.jumpkind))
                # sa.append("}")
                # for i in range(stm_used):
                #     z3_expr.append(irsb.statements[i])
                #     # print irsb.statements[i]
                #     # print handlesinwor(irsb.statements[i])

                # print [hex(int(x)) for x in addr_not_go]
            else:
                del addr_not_go[0]
        # ii = z3_expr
        # ii = pre_Handle(ii)
        # for item in ii:
        #     print item
        # print '---------------------------'

        # for item in z3_expr:
        #     print item


        import ExecuteIR_Z3

        eiz = ExecuteIR_Z3.executeIR_Z3(IR_INIT,IR_LOOP,IR_END,self.checksum,self.length)
        eiz.solve()
    # print IR_INIT