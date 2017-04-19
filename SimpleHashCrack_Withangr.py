import angr
import pyvex
import cle

from pyvex import stmt,expr

class find_loop_VEXIR():
    def __init__(self, start_addr, checksum, leng, executablefilename, arch='x86'):
        self.b = angr.Project(executablefilename, load_options={'auto_load_libs': False})
        self.ld = cle.Loader(executablefilename)
        self.checksum = checksum
        self.length = leng
        self.arch = arch
        self.cfg = self.b.analyses.CFGAccurate(keep_state=True)
        self.addr = start_addr
    def getIRSBfromBin(self,addr, data_len=0x100):
        # print hex(addr)
        some_text_data = "".join(self.ld.memory.read_bytes(addr, data_len))
        irsb = pyvex.IRSB(some_text_data, addr, self.ld.main_bin.arch)
        return irsb
# print cfg.graph
# print len(cfg.graph.nodes()),len(cfg.graph.edges())
#
# entry_node = cfg.get_any_node(addr)
#
# print 'contexts :' ,len(cfg.get_all_nodes(addr))
#
# print entry_node.predecessors
# print entry_node.successors

    def run(self):
# print [jumpkind + ' to ' +hex(node.addr) for node , jumpkind in cfg.get_successors_and_jumpkind(entry_node)]
        init_addr=[]
        loop_addr = []
        entry_func = self.cfg.kb.functions[self.addr]
        # print entry_func.block_addrs
        func_graph = entry_func.transition_graph
        # print func_graph
        graph_dic = {}
        edges = func_graph.edge
        for item in edges.keys():
            # print type(item)
            graph_dic[item.addr] = [x.addr for x in edges[item]]
            # print edges[item]

        #print graph_dic

        # for key in graph_dic.keys():
        #     print hex(key),':',
        #     for value in graph_dic[key]:
        #         print hex(value),
        #     print

        # print entry_func.returning\

        #Topologic Order
        ingree = {}
        is_delete = {}
        is_handle = []
        # dfs use is_visit
        is_visit = {}
        for key in graph_dic.keys():
            if (key not in is_handle):
                ingree[key] = 0
                is_delete[key] = 0
                is_handle.append(key)
            if (len(graph_dic[key])>0):
                for value_key in graph_dic[key]:
                    if (value_key in is_handle):
                        ingree[value_key] += 1
                    else:
                        is_delete[value_key] = 0
                        ingree[value_key] = 1
                    is_handle.append(value_key)
            else:
                is_delete[key] = 1
                is_handle.append(key)
        is_visit = is_delete.copy()
        # for item in ingree.keys():
        #     print hex(item),ingree[item]

        # print '---------------------'

        flag = True
        while (flag):

            flag = False
            for ingree_key in ingree.keys():
                if(is_delete[ingree_key] ==0 and ingree[ingree_key] <= 0 ):
                    is_delete[ingree_key] = 1
                    for pointed_value in graph_dic[ingree_key]:
                        ingree[pointed_value]-=1
                    flag = True
        # for item in is_delete.keys():
        #     print hex(item), is_delete[item]
        #seek minaddr_in loop ( not definitely loop start)
        # print 'after order'
        #get loop part
        LOOP_ADDR = []
        minaddr_in_loop = 100000000000
        for item in is_delete.keys():
            if(is_delete[item] == 0 and item < minaddr_in_loop):
                minaddr_in_loop = item
            # if(is_delete[item] == 0):
                # print hex(item),is_delete[item]
        LOOP_ADDR.append(minaddr_in_loop)
        #dfs seek INITPART
        INIT_ADDR = []

        for key in is_visit.keys():
            is_visit[key] = 0

        self.dfs_flag = 0

        def dfs_getInit(from_addr):
            if (is_delete[from_addr] == 0):
                self.dfs_flag = 1
                return 1
            is_visit[from_addr] = 1
            # print hex(from_addr) ,' = 1'
            # print 'dfsfrom',hex(from_addr)
            for nextnode in graph_dic[from_addr]:
                if (is_visit[nextnode]==0):
                    # print 'dfsto',hex(nextnode)
                    if dfs_getInit(nextnode)==1:
                        break
                    else:
                        if(self.dfs_flag == 0):
                          is_visit[nextnode] = 0
                          # print hex(nextnode) ,'=0'
            return 0
        # print 'after dfs'
        dfs_getInit(self.addr)

        #add InitPart

        flag = True

        def dfs_getInitIR(from_addr):
            if(is_visit[from_addr] == 1):
                # print 'add',hex(from_addr)
                INIT_ADDR.append((from_addr))
            else:
                return
            for nextnode in graph_dic[from_addr]:
                # print 'nextnode',hex(nextnode)
                dfs_getInitIR(nextnode)

        dfs_getInitIR(self.addr)

        #seek end part
        END_ADDR = []
        is_add = []
        def dfs_getEndAddr(addr):
            # print hex(addr)
            if (is_delete[addr] == 1):
                END_ADDR.append(addr)
            for nextnode in graph_dic[addr]:
                if (nextnode not in END_ADDR and is_delete[nextnode] != 0):
                    dfs_getEndAddr(nextnode)
        dfs_getEndAddr(minaddr_in_loop)
        # print 'INIT ADDR:'
        # for item in INIT_ADDR:
        #     print hex(item)
        # print "LOOP ADDR"
        # for item in LOOP_ADDR:
        #     print hex(item)
        # print 'end ----------'
        # for item in END_ADDR:
        #     print hex(item)
        INIT_IR = []
        LOOP_IR = []
        END_IR =  []
        for IR_ADDR in INIT_ADDR:
            irsb = self.getIRSBfromBin(IR_ADDR)
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
                INIT_IR.append(stmt_str)
        for IR_ADDR in LOOP_ADDR:
            irsb = self.getIRSBfromBin(IR_ADDR)
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
                LOOP_IR.append(stmt_str)
        for IR_ADDR in END_ADDR:
            irsb = self.getIRSBfromBin(IR_ADDR)
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
                END_IR.append(stmt_str)

        # for item in INIT_IR:
        #     print item
        # print 'loop -------------'
        #
        # for item in LOOP_IR:
        #     print item
        #
        # print 'end --------------'
        # for item in END_IR:
        #     print item

        import ExecuteIR_Z3

        eiz = ExecuteIR_Z3.executeIR_Z3(INIT_IR,LOOP_IR,END_IR,self.checksum,self.length,self.arch,self.ld)
        eiz.solve()



binname = 'x86_loginencryptdefault'
xxx = find_loop_VEXIR(0x4007E8,4284753089,3,'HelloWorld','x86')
xxx.run()
