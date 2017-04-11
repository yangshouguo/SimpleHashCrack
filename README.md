# SimpleHashCrack
crack very simple hash function

prepare jobs:
1 . install pyvex cle and z3 for python
    pyvex : https://github.com/angr/pyvex
    cle : https://github.com/angr/cle
    z3 : https://github.com/Z3Prover/z3
2 . download the folder 
3 . compile the .c file , then get the executable file , make sure than executable file in the same folder with python file
4 . use ida or some other software to get the start address of hash function , then you modify the test_crack.py , run it.
5 . if it works , it will show some password
