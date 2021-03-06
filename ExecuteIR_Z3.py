
from z3 import *
# this script can execute vexIR based on z3 prover
# vexIR should be divided 3 part : Init_part Loop_part End_part
# we think the function put the return value into reg rax

class executeIR_Z3:
    def __init__(self, init_part, loop_part, end_part, checksum , length):
        self.Init_part = init_part
        self.Loop_part = loop_part
        self.End_part  = end_part
        self.Checksum  = checksum
        self.Len       = length
        self.bit = 32
        self.reg_ax = ['rax' ,'eax' ,'al' ,'ah'] # treat all rax.... as eax
        self.exits_virable = [] # the exits virables to bi mian chong fu fu zhi
        self.password = [BitVec("b%d" % i, self.bit) for i in range(length)]
        for i in range(length):
            self.exits_virable.append('b%d' % i)
        self.param_reg = ['rdi'] #registers  that pass parameters
        self.param_addr = [] # parameter register address
        # chechsum is output of hash function
        # length is length of password
        self.var_allocate = {} #the z3 virables which has been allocate
    def is_alphanum(self ,x):
        return Or(And(x>= 0x41 , x<= 0x5a), And(x>= 0x61 , x<= 0x7a) ,And(x>=0x30,x<=0x39))

    def display_model(self, m):
        block = {}
        for x in m:
            if "b" in str(x):
                if (len(str(x))<3):
                    block[ord(str(x)[-1:])] = int(str(m[x]))
                else:
                    block[(ord(str(x)[-2])-48)*10+ord(str(x)[-1])] = int(str(m[x]))
        password = "".join(map(chr,block.values()))
        print password

    def get_models(self,F):
        s = Solver()
        s.add(F)
        while True:
            if s.check() == sat:
                m = s.model()
                self.display_model(m)
                block = []
                for d in m:
                    if d.arity()>0:
                        raise Z3Exception("uninterpreted functions are not supported")
                    c = d()
                    if is_array(c) or c.sort().kind()== Z3_UNINTERPRETED_SORT:
                        raise Z3Exception("arrays and uninterpreted sorts are not supported")
                    block.append(c != m[d])
                s.add(Or(block))
            else:
                print 'done'
                break

    def solve(self):
        checksum = BitVec('checksum',self.bit)
        F = []
        F.extend([self.is_alphanum(self.password[i])for  i in range(self.Len)])
        checksum_num = self.Checksum
        F.extend([
            checksum == checksum_num,
            self.dostrcmd() == checksum
        ])
        print F
        self.get_models(F)

    def createVira(self,name):
        strcmd = name + " = self.IRtoZ3exprVira('%s')" % name
        exec strcmd
    def IRtoZ3exprVira(self,var):  # if var is number , return a number , else return a z3expr
        self.exits_virable.append(var)
        if (var in self.var_allocate):
            return self.var_allocate["%s" % var]
        x = str(var)

        if ("0x" in x):
            return BitVecVal(int(x[4:],16),32)
        elif (x[-1] == 'h'):
            x = x[0:-1]
            x = '0x'+x
            return int(x)
        else:
            if (x not in self.var_allocate):
                # exec "global %s" % x
                strcmd = "%s = BitVec('%s',self.bit)" % (x, x)
                exec strcmd
                self.var_allocate["%s" % x] = eval(x)
                return eval(x)
            else:
                return self.var_allocate["%s" % x]




    def getparamInch(self,statemet):
        param = []
        l = statemet.find("(")
        r = statemet.find(")")
        if l<0 or r<0:
            return param
        mid = statemet.find(",")
        if mid<r and mid > l:
            param.append(statemet[l+1:mid])
            param.append(statemet[mid+1:r])
        else:
            param.append(statemet[l+1:r])
        return param

    def numtovira(self,numstr):
        if ('0x' in numstr or numstr.isdigit()):
            numstr = 'num_'+numstr

        return numstr
    def storepos(self,str): #to make STle(t6) = t0  into  STle(t7_8) = t0  then  get  t7_8 = t0
        self.op = ['+','-','*']
        str2 = ""
        for i in range(len(str)):
            if(str[i] in self.op ):
                str2+='_'
            elif(str[i] ==' '):
                continue
            else:
                str2+=str[i]
        return str2


    def dostrcmd(self):

        # change a IRVEX statement into a string cmd to execute
        # write them all to a loop for then can all live
        for item in self.Init_part:
            if ("=" not in item or 'if' in item or 'AbiHint' in item):
                continue
            strcmd = ""
            parts = (item).split(" ")



            if( 'GET' in item):
                para = self.getparamInch(item)[0]
                if(para not in self.exits_virable):#
                    strcmd = para + " = self.IRtoZ3exprVira(para)"
                    exec strcmd

                if (parts[0] not in self.exits_virable):
                    strcmd = parts[0] + " = self.IRtoZ3exprVira(parts[0])"
                    exec strcmd

                strcmd = str(parts[0]) + "=" + str(para)

                if (para == 'al'):
                    strcmd = parts[0] +'= rax & 0xff'
                exec strcmd

            elif('Sub' in item):

                para = self.getparamInch(item)
                para[0] = self.numtovira(para[0])
                para[1] = self.numtovira(para[1])
                if (para[0] not in self.exits_virable):
                    strcmd = para[0] + " = self.IRtoZ3exprVira(para[0])"
                    exec strcmd

                if (para[1] not in self.exits_virable):
                    strcmd = para[1] + " = self.IRtoZ3exprVira(para[1])"
                    exec strcmd

                if (parts[0] not in self.exits_virable):
                    strcmd = parts[0] + " = self.IRtoZ3exprVira(parts[0])"
                    exec strcmd

                strcmd = parts[0] + '=' + para[0]+"-"+para[1]
                exec strcmd
            elif("Add" in item):

                para = self.getparamInch(item)
                para[0] = self.numtovira(para[0])
                para[1] = self.numtovira(para[1])
                if (para[0] not in self.exits_virable):
                    strcmd = para[0] + " = self.IRtoZ3exprVira(para[0])"
                    exec strcmd

                if (para[1] not in self.exits_virable):
                    strcmd = para[1] + " = self.IRtoZ3exprVira(para[1])"
                    exec strcmd

                if (parts[0] not in self.exits_virable):
                    strcmd = parts[0] + " = self.IRtoZ3exprVira(parts[0])"
                    exec strcmd

                strcmd = parts[0] + '=' + para[0] + "+" + para[1]
                exec strcmd

            elif ("STle" in item): # STle(t6) = t0  --->  t7_8=t0
                parts[2] = self.numtovira(parts[2])
                if (parts[2] not in self.exits_virable):
                    strcmd = parts[2] + " = self.IRtoZ3exprVira(parts[2])"
                    exec strcmd

                para = self.getparamInch(item)
                strcmd = 'tmp = eval(para[0])'
                exec strcmd
                tmp = self.storepos(str(tmp))
                if (str(eval(parts[2])) in self.param_reg):
                    self.param_addr.append(tmp)
                if (tmp not in self.exits_virable):
                    strcmd = tmp + " = self.IRtoZ3exprVira(tmp)"
                    exec strcmd

                strcmd = tmp + '=' + parts[2]
                exec strcmd
                # strcmd = para + " = self.IRtoZ3exprVira(para)"
                # print strcmd
                # exec strcmd

            elif("LDle" in item):
                if (parts[0] not in self.exits_virable):
                    strcmd = parts[0] + " = self.IRtoZ3exprVira(parts[0])"
                    exec strcmd

                para = self.getparamInch(item)
                strcmd = 'tmp = eval(para[0])'
                exec strcmd
                tmp = self.storepos(str(tmp))
                if(len(tmp) > 4):
                    strcmd = parts[0] + '=' + tmp
                else:
                    strcmd = parts[0] + '=' + para[0]
                if (tmp not in self.exits_virable):
                    strcmd = tmp + " = self.IRtoZ3exprVira(tmp)"
                    exec strcmd

                exec strcmd
            elif('PUT' in item): # PUT(rsp) = t6
                para = self.getparamInch(item)
                if (para[0] not in self.exits_virable):
                    strcmd = (para[0] + '=' + "self.IRtoZ3exprVira('%s')" % para[0])
                    self.exits_virable.append(para[0])
                parts[2] = self.numtovira(parts[2])
                if (parts[2] not in self.exits_virable):
                    strcmd = parts[2] + "= self.IRtoZ3exprVira(parts[2])"
                    exec strcmd
                strcmd = para[0] + '=' +parts[2]
                exec strcmd
            elif('to' in item):
                para = self.getparamInch(item)
                if(parts[0] not in self.exits_virable):
                    strcmd = parts[0] + "= self.IRtoZ3exprVira(parts[0])"
                    exec strcmd
                strcmd = parts[0] + '=' + para[0]
                exec strcmd
            elif ('And' in item):

                para = self.getparamInch(item)
                para[0] = self.numtovira(para[0])
                para[1] = self.numtovira(para[1])
                if (para[0] not in self.exits_virable):
                    strcmd = para[0] + " = self.IRtoZ3exprVira(para[0])"
                    exec strcmd

                if (para[1] not in self.exits_virable):
                    strcmd = para[1] + " = self.IRtoZ3exprVira(para[1])"
                    exec strcmd

                if (parts[0] not in self.exits_virable):
                    strcmd = parts[0] + " = self.IRtoZ3exprVira(parts[0])"
                    exec strcmd

                strcmd = parts[0] + '=' + para[0] + "&" + para[1]
                exec strcmd
            elif("CmpEQ" in item):# do nothing
                if (parts[0] not in self.exits_virable):
                    strcmd = parts[0] + " = self.IRtoZ3exprVira(parts[0])"
                    exec strcmd
                strcmd = parts[0] +'= 0'
                exec strcmd

            elif ("CmpLT" in item):
                para = self.getparamInch(item)
                para[0] = self.numtovira(para[0])
                para[1] = self.numtovira(para[1])
                if (para[0] not in self.exits_virable):
                    strcmd = para[0] + " = self.IRtoZ3exprVira(para[0])"
                    exec strcmd

                if (para[1] not in self.exits_virable):
                    strcmd = para[1] + " = self.IRtoZ3exprVira(para[1])"
                    exec strcmd

                if (parts[0] not in self.exits_virable):
                    strcmd = parts[0] + " = self.IRtoZ3exprVira(parts[0])"
                    exec strcmd

                strcmd = parts[0] + '=' + para[0] + "-" + para[1]
                exec strcmd
            elif ("Xor" in item):
                para = self.getparamInch(item)
                para[0] = self.numtovira(para[0])
                para[1] = self.numtovira(para[1])
                if (para[0] not in self.exits_virable):
                    strcmd = para[0] + " = self.IRtoZ3exprVira(para[0])"
                    exec strcmd

                if (para[1] not in self.exits_virable):
                    strcmd = para[1] + " = self.IRtoZ3exprVira(para[1])"
                    exec strcmd

                if (parts[0] not in self.exits_virable):
                    strcmd = parts[0] + " = self.IRtoZ3exprVira(parts[0])"
                    exec strcmd

                strcmd = parts[0] + '=' + para[0] + "^" + para[1]
                exec strcmd
            elif ("Shl" in item):
                para = self.getparamInch(item)
                para[0] = self.numtovira(para[0])
                para[1] = self.numtovira(para[1])
                if (para[0] not in self.exits_virable):
                    strcmd = para[0] + " = self.IRtoZ3exprVira(para[0])"
                    exec strcmd

                if (para[1] not in self.exits_virable):
                    strcmd = para[1] + " = self.IRtoZ3exprVira(para[1])"
                    exec strcmd

                if (parts[0] not in self.exits_virable):
                    strcmd = parts[0] + " = self.IRtoZ3exprVira(parts[0])"
                    exec strcmd

                strcmd = parts[0] + '=' + para[0] + "<<" + para[1]
                exec strcmd
            elif ('Shr' in item):
                para = self.getparamInch(item)
                para[0] = self.numtovira(para[0])
                para[1] = self.numtovira(para[1])
                if (para[0] not in self.exits_virable):
                    strcmd = para[0] + " = self.IRtoZ3exprVira(para[0])"
                    exec strcmd

                if (para[1] not in self.exits_virable):
                    strcmd = para[1] + " = self.IRtoZ3exprVira(para[1])"
                    exec strcmd

                if (parts[0] not in self.exits_virable):
                    strcmd = parts[0] + " = self.IRtoZ3exprVira(parts[0])"
                    exec strcmd

                strcmd = parts[0] + '=' + para[0] + ">>" + para[1]
                exec strcmd
            elif ("CmpLT" in item or 'CmpNE' in item):
                para = self.getparamInch(item)
                para[0] = self.numtovira(para[0])
                para[1] = self.numtovira(para[1])
                if (para[0] not in self.exits_virable):
                    strcmd = para[0] + " = self.IRtoZ3exprVira(para[0])"
                    exec strcmd

                if (para[1] not in self.exits_virable):
                    strcmd = para[1] + " = self.IRtoZ3exprVira(para[1])"
                    exec strcmd

                if (parts[0] not in self.exits_virable):
                    strcmd = parts[0] + " = self.IRtoZ3exprVira(parts[0])"
                    exec strcmd

                strcmd = parts[0] + '=' + para[0] + "-" + para[1]
                exec strcmd
            else:
                if (parts[0] not in self.exits_virable):
                    strcmd = parts[0] + " = self.IRtoZ3exprVira(parts[0])"
                    exec strcmd
                strcmd = parts[0] + '=' + "self.IRtoZ3exprVira('%s')" % parts[2]
                exec strcmd


        #LOOP
        for i in range(self.Len):
            for item in self.Loop_part:
                if ("=" not in item or 'if' in item or 'AbiHint' in item):
                    continue
                strcmd = ""
                parts = (item).split(" ")

                if ('GET' in item):
                    para = self.getparamInch(item)[0]
                    if (para not in self.exits_virable):  #
                        strcmd = para + " = self.IRtoZ3exprVira(para)"
                        exec strcmd

                    if (parts[0] not in self.exits_virable):
                        strcmd = parts[0] + " = self.IRtoZ3exprVira(parts[0])"
                        exec strcmd

                    strcmd = str(parts[0]) + "=" + str(para)

                    if (para == 'al' or para == 'ah'):
                        # strcmd = parts[0] + '= rax & 0xff'
                        strcmd = parts[0] + '= rax '
                    if (para == 'cl' or para == 'ch'):
                        # strcmd = parts[0] + '= rax & 0xff'
                        strcmd = parts[0] + '= rcx '
                    if (para == 'bl' or para == 'bh'):
                        # strcmd = parts[0] + '= rax & 0xff'
                        strcmd = parts[0] + '= rbx '
                    if (para == 'dl' or para == 'dh'):
                        # strcmd = parts[0] + '= rax & 0xff'
                        strcmd = parts[0] + '= rdx '

                    exec strcmd

                elif ('Sub' in item):

                    para = self.getparamInch(item)
                    para[0] = self.numtovira(para[0])
                    para[1] = self.numtovira(para[1])
                    if (para[0] not in self.exits_virable):
                        strcmd = para[0] + " = self.IRtoZ3exprVira(para[0])"
                        exec strcmd

                    if (para[1] not in self.exits_virable):
                        strcmd = para[1] + " = self.IRtoZ3exprVira(para[1])"
                        exec strcmd

                    if (parts[0] not in self.exits_virable):
                        strcmd = parts[0] + " = self.IRtoZ3exprVira(parts[0])"
                        exec strcmd

                    strcmd = parts[0] + '=' + para[0] + "-" + para[1]
                    exec strcmd
                elif ("Add" in item):

                    para = self.getparamInch(item)
                    para[0] = self.numtovira(para[0])
                    para[1] = self.numtovira(para[1])
                    if (para[0] not in self.exits_virable):
                        strcmd = para[0] + " = self.IRtoZ3exprVira(para[0])"
                        exec strcmd

                    if (para[1] not in self.exits_virable):
                        strcmd = para[1] + " = self.IRtoZ3exprVira(para[1])"
                        exec strcmd

                    if (parts[0] not in self.exits_virable):
                        strcmd = parts[0] + " = self.IRtoZ3exprVira(parts[0])"
                        exec strcmd

                    strcmd = parts[0] + '=' + para[0] + "+" + para[1]
                    exec strcmd

                elif ("STle" in item):  # STle(t6) = t0  --->  t7_8=t0
                    parts[2] = self.numtovira(parts[2])
                    if (parts[2] not in self.exits_virable):
                        strcmd = parts[2] + " = self.IRtoZ3exprVira(parts[2])"
                        exec strcmd

                    para = self.getparamInch(item)
                    strcmd = 'tmp = eval(para[0])'
                    exec strcmd
                    tmp = self.storepos(str(tmp))

                    if (tmp not in self.exits_virable):
                        strcmd = tmp + " = self.IRtoZ3exprVira(tmp)"
                        exec strcmd

                    strcmd = tmp + '=' + parts[2]
                    exec strcmd
                    # strcmd = para + " = self.IRtoZ3exprVira(para)"
                    # print strcmd
                    # exec strcmd

                elif ("LDle" in item):
                    if (parts[0] not in self.exits_virable):
                        strcmd = parts[0] + " = self.IRtoZ3exprVira(parts[0])"
                        exec strcmd

                    para = self.getparamInch(item)
                    strcmd = 'tmp = eval(para[0])'
                    exec strcmd
                    tmp = self.storepos(str(tmp))

                    if (tmp not in self.exits_virable):
                        strcmd = tmp + " = self.IRtoZ3exprVira(tmp)"
                        exec strcmd
                    strcmd = parts[0] + '=' + tmp
                    if(len(tmp) <4):
                        strcmd = parts[0] + '=' +para[0]
                    if(tmp in self.param_addr):
                        strcmd = parts[0] + "= self.password[i]"
                    exec strcmd
                elif ('PUT' in item):  # PUT(rsp) = t6
                    para = self.getparamInch(item)
                    if (para[0] not in self.exits_virable):
                        strcmd = (para[0] + '=' + "self.IRtoZ3exprVira('%s')" % para[0])
                        self.exits_virable.append(para[0])
                    parts[2] = self.numtovira(parts[2])
                    if (parts[2] not in self.exits_virable):
                        strcmd = parts[2] + "= self.IRtoZ3exprVira(parts[2])"
                        exec strcmd
                    strcmd = para[0] + '=' + parts[2]
                    exec strcmd
                elif ('to' in item):
                    para = self.getparamInch(item)
                    if (parts[0] not in self.exits_virable):
                        strcmd = parts[0] + "= self.IRtoZ3exprVira(parts[0])"
                        exec strcmd
                    strcmd = parts[0] + '=' + para[0]
                    exec strcmd
                elif ('Mul' in item):
                    para = self.getparamInch(item)
                    para[0] = self.numtovira(para[0])
                    para[1] = self.numtovira(para[1])
                    if (para[0] not in self.exits_virable):
                        strcmd = para[0] + " = self.IRtoZ3exprVira(para[0])"
                        exec strcmd

                    if (para[1] not in self.exits_virable):
                        strcmd = para[1] + " = self.IRtoZ3exprVira(para[1])"
                        exec strcmd

                    if (parts[0] not in self.exits_virable):
                        strcmd = parts[0] + " = self.IRtoZ3exprVira(parts[0])"
                        exec strcmd

                    strcmd = parts[0] + '=' + para[0] + "*" + para[1]
                    exec strcmd
                elif ('Shr' in item):
                    para = self.getparamInch(item)
                    para[0] = self.numtovira(para[0])
                    para[1] = self.numtovira(para[1])
                    if (para[0] not in self.exits_virable):
                        strcmd = para[0] + " = self.IRtoZ3exprVira(para[0])"
                        exec strcmd

                    if (para[1] not in self.exits_virable):
                        strcmd = para[1] + " = self.IRtoZ3exprVira(para[1])"
                        exec strcmd

                    if (parts[0] not in self.exits_virable):
                        strcmd = parts[0] + " = self.IRtoZ3exprVira(parts[0])"
                        exec strcmd
                    # strcmd = "isint = isinstance(para[0], BitVecRef)"
                    # exec strcmd
                    # if(not isint):
                    #     strcmd = "para[0] = "
                    strcmd = parts[0] + '= LShR(' + para[0] + "," + "2"+")"
                    exec strcmd
                elif ('And' in item):

                    para = self.getparamInch(item)
                    para[0] = self.numtovira(para[0])
                    para[1] = self.numtovira(para[1])
                    if (para[0] not in self.exits_virable):
                        strcmd = para[0] + " = self.IRtoZ3exprVira(para[0])"
                        exec strcmd

                    if (para[1] not in self.exits_virable):
                        strcmd = para[1] + " = self.IRtoZ3exprVira(para[1])"
                        exec strcmd

                    if (parts[0] not in self.exits_virable):
                        strcmd = parts[0] + " = self.IRtoZ3exprVira(parts[0])"
                        exec strcmd

                    strcmd = parts[0] + '=' + para[0] + "&" + para[1]
                    exec strcmd
                elif ("CmpEQ" in item):  # do nothing
                    if (parts[0] not in self.exits_virable):
                        strcmd = parts[0] + " = self.IRtoZ3exprVira(parts[0])"
                        exec strcmd
                    strcmd = parts[0] + '= 0'
                    exec strcmd
                elif ("CmpLT" in item):
                    para = self.getparamInch(item)
                    para[0] = self.numtovira(para[0])
                    para[1] = self.numtovira(para[1])
                    if (para[0] not in self.exits_virable):
                        strcmd = para[0] + " = self.IRtoZ3exprVira(para[0])"
                        exec strcmd

                    if (para[1] not in self.exits_virable):
                        strcmd = para[1] + " = self.IRtoZ3exprVira(para[1])"
                        exec strcmd

                    if (parts[0] not in self.exits_virable):
                        strcmd = parts[0] + " = self.IRtoZ3exprVira(parts[0])"
                        exec strcmd

                    strcmd = parts[0] + '=' + para[0] + "-" + para[1]
                    exec strcmd
                elif ("Xor" in item):
                    para = self.getparamInch(item)
                    para[0] = self.numtovira(para[0])
                    para[1] = self.numtovira(para[1])
                    if (para[0] not in self.exits_virable):
                        strcmd = para[0] + " = self.IRtoZ3exprVira(para[0])"
                        exec strcmd

                    if (para[1] not in self.exits_virable):
                        strcmd = para[1] + " = self.IRtoZ3exprVira(para[1])"
                        exec strcmd

                    if (parts[0] not in self.exits_virable):
                        strcmd = parts[0] + " = self.IRtoZ3exprVira(parts[0])"
                        exec strcmd

                    strcmd = parts[0] + '=' + para[0] + "^" + para[1]
                    exec strcmd
                elif ("Shl" in item):
                    para = self.getparamInch(item)
                    para[0] = self.numtovira(para[0])
                    para[1] = self.numtovira(para[1])
                    if (para[0] not in self.exits_virable):
                        strcmd = para[0] + " = self.IRtoZ3exprVira(para[0])"
                        exec strcmd

                    if (para[1] not in self.exits_virable):
                        strcmd = para[1] + " = self.IRtoZ3exprVira(para[1])"
                        exec strcmd

                    if (parts[0] not in self.exits_virable):
                        strcmd = parts[0] + " = self.IRtoZ3exprVira(parts[0])"
                        exec strcmd

                    strcmd = parts[0] + '=' + para[0] + "<<" + para[1]
                    exec strcmd
                elif ("Or" in item):
                    para = self.getparamInch(item)
                    para[0] = self.numtovira(para[0])
                    para[1] = self.numtovira(para[1])
                    if (para[0] not in self.exits_virable):
                        strcmd = para[0] + " = self.IRtoZ3exprVira(para[0])"
                        exec strcmd

                    if (para[1] not in self.exits_virable):
                        strcmd = para[1] + " = self.IRtoZ3exprVira(para[1])"
                        exec strcmd

                    if (parts[0] not in self.exits_virable):
                        strcmd = parts[0] + " = self.IRtoZ3exprVira(parts[0])"
                        exec strcmd

                    strcmd = parts[0] + '=' + para[0] + "|" + para[1]
                    exec strcmd
                else:
                    if ("flag" in item):
                        if (parts[0] not in self.exits_virable):
                            strcmd = parts[0] + " = self.IRtoZ3exprVira(parts[0])"
                            exec strcmd
                        continue
                    if (parts[0] not in self.exits_virable):
                        strcmd = parts[0] + " = self.IRtoZ3exprVira(parts[0])"
                        exec strcmd
                    if(parts[2] not in self.exits_virable):
                        strcmd = parts[2] + " = self.IRtoZ3exprVira(parts[2])"
                        exec strcmd
                    strcmd = parts[0] + '=' + parts[2]
                    exec strcmd
        # print rsp_8_4294967288
        for item in self.End_part:
            if ("=" not in item or 'if' in item or 'AbiHint' in item):
                continue
            strcmd = ""
            parts = (item).split(" ")

            if ('GET' in item):
                para = self.getparamInch(item)[0]
                if (para not in self.exits_virable):  #
                    strcmd = para + " = self.IRtoZ3exprVira(para)"
                    exec strcmd

                if (parts[0] not in self.exits_virable):
                    strcmd = parts[0] + " = self.IRtoZ3exprVira(parts[0])"
                    exec strcmd

                strcmd = str(parts[0]) + "=" + str(para)

                if (para == 'al'):
                    # strcmd = parts[0] + '= rax & 0xff'
                    strcmd = parts[0] + '= rax '

                exec strcmd

            elif ('Sub' in item):

                para = self.getparamInch(item)
                para[0] = self.numtovira(para[0])
                para[1] = self.numtovira(para[1])
                if (para[0] not in self.exits_virable):
                    strcmd = para[0] + " = self.IRtoZ3exprVira(para[0])"
                    exec strcmd

                if (para[1] not in self.exits_virable):
                    strcmd = para[1] + " = self.IRtoZ3exprVira(para[1])"
                    exec strcmd

                if (parts[0] not in self.exits_virable):
                    strcmd = parts[0] + " = self.IRtoZ3exprVira(parts[0])"
                    exec strcmd

                strcmd = parts[0] + '=' + para[0] + "-" + para[1]
                exec strcmd
            elif ("Add" in item):

                para = self.getparamInch(item)
                para[0] = self.numtovira(para[0])
                para[1] = self.numtovira(para[1])
                if (para[0] not in self.exits_virable):
                    strcmd = para[0] + " = self.IRtoZ3exprVira(para[0])"
                    exec strcmd

                if (para[1] not in self.exits_virable):
                    strcmd = para[1] + " = self.IRtoZ3exprVira(para[1])"
                    exec strcmd

                if (parts[0] not in self.exits_virable):
                    strcmd = parts[0] + " = self.IRtoZ3exprVira(parts[0])"
                    exec strcmd

                strcmd = parts[0] + '=' + para[0] + "+" + para[1]
                exec strcmd

            elif ("STle" in item):  # STle(t6) = t0  --->  t7_8=t0
                parts[2] = self.numtovira(parts[2])
                if (parts[2] not in self.exits_virable):
                    strcmd = parts[2] + " = self.IRtoZ3exprVira(parts[2])"
                    exec strcmd

                para = self.getparamInch(item)
                strcmd = 'tmp = eval(para[0])'
                exec strcmd
                tmp = self.storepos(str(tmp))

                if (tmp not in self.exits_virable):
                    strcmd = tmp + " = self.IRtoZ3exprVira(tmp)"
                    exec strcmd

                strcmd = tmp + '=' + parts[2]
                exec strcmd
                # strcmd = para + " = self.IRtoZ3exprVira(para)"
                # print strcmd
                # exec strcmd

            elif ("LDle" in item):
                if (parts[0] not in self.exits_virable):
                    strcmd = parts[0] + " = self.IRtoZ3exprVira(parts[0])"
                    exec strcmd

                para = self.getparamInch(item)
                strcmd = 'tmp = eval(para[0])'
                exec strcmd
                tmp = self.storepos(str(tmp))
                tmp = self.numtovira(tmp)
                if (tmp not in self.exits_virable):
                    strcmd = tmp + " = self.IRtoZ3exprVira(tmp)"
                    exec strcmd
                strcmd = parts[0] + '=' + tmp
                if (len(tmp) < 4):
                    strcmd = parts[0] + '=' + para[0]
                if (tmp in self.param_addr):
                    strcmd = parts[0] + "= self.password[i]"
                exec strcmd
            elif ('PUT' in item):  # PUT(rsp) = t6
                para = self.getparamInch(item)
                if (para[0] not in self.exits_virable):
                    strcmd = (para[0] + '=' + "self.IRtoZ3exprVira('%s')" % para[0])
                    self.exits_virable.append(para[0])
                parts[2] = self.numtovira(parts[2])
                if (parts[2] not in self.exits_virable):
                    strcmd = parts[2] + "= self.IRtoZ3exprVira(parts[2])"
                    exec strcmd
                strcmd = para[0] + '=' + parts[2]
                exec strcmd
            elif ('to' in item):
                para = self.getparamInch(item)
                if (parts[0] not in self.exits_virable):
                    strcmd = parts[0] + "= self.IRtoZ3exprVira(parts[0])"
                    exec strcmd
                strcmd = parts[0] + '=' + para[0]
                exec strcmd
            elif ('Mul' in item):
                para = self.getparamInch(item)
                para[0] = self.numtovira(para[0])
                para[1] = self.numtovira(para[1])
                if (para[0] not in self.exits_virable):
                    strcmd = para[0] + " = self.IRtoZ3exprVira(para[0])"
                    exec strcmd

                if (para[1] not in self.exits_virable):
                    strcmd = para[1] + " = self.IRtoZ3exprVira(para[1])"
                    exec strcmd

                if (parts[0] not in self.exits_virable):
                    strcmd = parts[0] + " = self.IRtoZ3exprVira(parts[0])"
                    exec strcmd

                strcmd = parts[0] + '=' + para[0] + "*" + para[1]
                exec strcmd
            elif ('Shr' in item):
                para = self.getparamInch(item)
                para[0] = self.numtovira(para[0])
                para[1] = self.numtovira(para[1])
                if (para[0] not in self.exits_virable):
                    strcmd = para[0] + " = self.IRtoZ3exprVira(para[0])"
                    exec strcmd

                if (para[1] not in self.exits_virable):
                    strcmd = para[1] + " = self.IRtoZ3exprVira(para[1])"
                    exec strcmd

                if (parts[0] not in self.exits_virable):
                    strcmd = parts[0] + " = self.IRtoZ3exprVira(parts[0])"
                    exec strcmd

                strcmd = parts[0] + '=' + para[0] + ">>" + para[1]
                exec strcmd
            elif ('And' in item):

                para = self.getparamInch(item)
                para[0] = self.numtovira(para[0])
                para[1] = self.numtovira(para[1])
                if (para[0] not in self.exits_virable):
                    strcmd = para[0] + " = self.IRtoZ3exprVira(para[0])"
                    exec strcmd

                if (para[1] not in self.exits_virable):
                    strcmd = para[1] + " = self.IRtoZ3exprVira(para[1])"
                    exec strcmd

                if (parts[0] not in self.exits_virable):
                    strcmd = parts[0] + " = self.IRtoZ3exprVira(parts[0])"
                    exec strcmd

                strcmd = parts[0] + '=' + para[0] + "&" + para[1]
                exec strcmd
            elif ("CmpEQ" in item):  # do nothing
                if (parts[0] not in self.exits_virable):
                    strcmd = parts[0] + " = self.IRtoZ3exprVira(parts[0])"
                    exec strcmd
                strcmd = parts[0] + '= 0'
                exec strcmd
            else:
                if (parts[0] not in self.exits_virable):
                    strcmd = parts[0] + " = self.IRtoZ3exprVira(parts[0])"
                    exec strcmd
                if (parts[2] not in self.exits_virable):
                    strcmd = parts[2] + " = self.IRtoZ3exprVira(parts[2])"
                    exec strcmd
                strcmd = parts[0] + '=' + parts[2]
                exec strcmd
        return rax


#-----test-----


# eee = executeIR_Z3([],[],[],1,1)
# eee.execute()
