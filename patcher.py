from ghidra.app.plugin.assembler import Assemblers
from ghidra.program.flatapi import FlatProgramAPI

import binascii
import subprocess

from __main__ import currentProgram

#import binascii
#load_code = binascii.unhexlify('5756505f488d35e8ffffffe8aaf433015e5f')

# TODO: change call strcpy address to be resolved dynamically
load_asm_header = [
    'PUSH RSI',
    'PUSH RDI',
    'PUSH RAX'
]

load_asm_footer = [
    'POP RDI',
    'POP RSI'
]

def generate_asm(ss, reg, off, call_addr):
    asm = [
        #'PUSH 0x9',
        #'POP RSI',
        'LEA RSI, [0x9]',
        'JMP %s' % hex(len(ss) + 2)
    ]

    asm.extend(load_asm_header)

    header, footer = [], []

    if off == 0 and reg.lower() == 'rax':
        header = ['POP RDI']
    elif off == 0:
        header = ['PUSH %s' % reg, 'POP RDI']
        footer = ['POP RAX']
    else:
        #header = ['LEA RDI, [%s + %s]' % (reg, hex(off))]
        header = [
            'PUSH %s' % reg,
            'POP RDI',
            'ADD RDI, %s' % hex(off)
        ]
        footer = ['POP RAX']

    asm.extend(header)
    asm.extend([
        'CALL %s' % (hex(call_addr.offset))
    ])
    asm.extend(footer)
    asm.extend(load_asm_footer)

    return asm


def assemble_insn(insn, at=None):
    # TODO: try clearing the listing and assembling -- should get rid of the context that's borking us
    args = ['rasm2', '-a', 'x86', '-b', '64']

    if at is not None:
        args.extend(['-@', hex(at)])
        #print('Assembling %s at %s' % (insn, hex(at)))

    args.append(insn)
    out = subprocess.check_output(args).strip()

    return [ord(d) for d in binascii.unhexlify(out)]


def get_load_bytes(asm, start):
    bs = []
    curr_off = start
    jmp_off = curr_off

    jmp_bs = assemble_insn(asm[0])
    #jmp_bs.extend(assemble_insn(asm[1]))
    curr_off += len(jmp_bs)

    jmp_bs.extend(assemble_insn(asm[1]))
    curr_off += jmp_bs[-1] + 2

    main_off = curr_off

    for line in asm[2:]:
        insn_bs = assemble_insn(line, curr_off)
        bs.extend(insn_bs)
        curr_off += len(insn_bs)

    return [(jmp_off, jmp_bs), (main_off, bs)]


def patch(bs, off):
    # I hate python2
    #assembler.patchProgram(bytes(bytearray(bs)), fp.toAddr(off))
    fp.clearListing(fp.toAddr(off), fp.toAddr(off + len(bs)))
    text_blk.setWrite(True)
    text_blk.putBytes(fp.toAddr(off), bytes(bytearray(bs)))
    text_blk.setWrite(False)


cp = currentProgram
fp = FlatProgramAPI(cp)
assembler = Assemblers.getAssembler(cp.language)

text_blk = [blk for blk in cp.memory.blocks if blk.name == '__text'][0]
