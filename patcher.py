from ghidra.program.flatapi import FlatProgramAPI

import binascii
import subprocess

from __main__ import currentProgram

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
    asm = [i for i in load_asm_header]

    asm.extend([
        'LEA RSI, [0x9]',
        'JMP %s' % hex(len(ss) + 2)
    ])

    header, footer = [], []

    if off == 0 and reg.lower() == 'rax':
        header = ['POP RDI']
    elif off == 0:
        header = ['PUSH %s' % reg, 'POP RDI']
        footer = ['POP RAX']
    else:
        header = [
            'LEA RDI, [%s + %s]' % (reg, hex(off))
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
    args = ['rasm2', '-a', 'x86', '-b', '64']

    if at is not None:
        args.extend(['-@', hex(at)])

    args.append(insn)
    out = subprocess.check_output(args).strip()

    return [ord(d) for d in binascii.unhexlify(out)]


def get_load_bytes(asm, start):
    bs = []
    curr_off = start
    jmp_off = curr_off

    jmp_bs = []

    for i in range(4):
        curr_bs = assemble_insn(asm[i])
        jmp_bs.extend(curr_bs)
        curr_off += len(curr_bs)

    jmp_bs.extend(assemble_insn(asm[4]))
    curr_off += jmp_bs[-1] + 2

    main_off = curr_off

    for line in asm[5:]:
        insn_bs = assemble_insn(line, curr_off)
        bs.extend(insn_bs)
        curr_off += len(insn_bs)

    return [(jmp_off, jmp_bs), (main_off, bs)]


def patch(bs, off):
    # Clear the bytes first
    fp.clearListing(fp.toAddr(off), fp.toAddr(off + len(bs)))

    # Enable writing for the section
    text_blk.setWrite(True)

    # I hate python2
    text_blk.putBytes(fp.toAddr(off), bytes(bytearray(bs)))

    # Restore the the permissions
    text_blk.setWrite(False)


cp = currentProgram
fp = FlatProgramAPI(cp)

text_blk = [blk for blk in cp.memory.blocks if blk.name == '__text'][0]
