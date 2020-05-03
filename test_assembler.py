from ghidra.app.plugin.assembler import Assemblers
from ghidra.program.flatapi import FlatProgramAPI

cp = currentProgram
fp = FlatProgramAPI(cp)
assembler = Assemblers.getAssembler(cp)

while True:
    asm = askString('', '', '')
    print(asm)
    print(assembler.assembleLine(fp.toAddr(0), asm))
