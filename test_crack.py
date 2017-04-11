import SimpleHashCrack
addr = 0x400586 # start address of hash function
checksum = 367223308 # output of hash function (unsigned int)
length = 6 #(password length)
executablefile = 'HelloWorld' # bin file name
crack = SimpleHashCrack.SimpleHashCrash(addr,checksum,length,executablefile)
crack.crask()
