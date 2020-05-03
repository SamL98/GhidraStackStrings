from ghidra.program.flatapi import FlatProgramAPI
from ghidra.program.model.pcode import PcodeOp
from ghidra.util.task import TaskMonitor

import math
import string
import struct as st

from pcode_utils import *
from patcher import *

def get_intersection(s1, s2, s1_off, s2_off):
    if s2_off < s1_off:
        s1, s2 = s2, s1
        s1_off, s2_off = s2_off, s1_off

    return s2_off - (s1_off + len(s1))

def merge(s1, s2, s1_off, s2_off):
    if s2_off < s1_off:
        s1, s2 = s2, s1
        s1_off, s2_off = s2_off, s1_off

    overlap = get_intersection(s1, s2, s1_off, s2_off)
    return s1[:len(s1) + min(overlap, 0)] + s2

def merge_insns(all_insns, new_insn):
    o = new_insn.address.offset
    l = new_insn.length
    e = o + l

    for i, (start, end) in enumerate(all_insns):
        if min(e, end) - max(o, start) >= 0:
            all_insns[i] = (min(o, start), max(e, end))
            return all_insns

    # this means we didn't have a matching block
    all_insns.append((o, e))
    all_insns = sorted(all_insns, key=lambda i: i[0])
    return all_insns


ca = currentAddress
cp = currentProgram
fp = FlatProgramAPI(cp)

fn = fp.getFunctionContaining(ca)
cont_fn = fn

if fn is None:
    print('Could not get function containing %x' % ca.offset)
    exit()

entry = fn.getEntryPoint()
insn = fp.getInstructionAt(entry)

#looking_for_ss = True
found_ss = False
ss_reg, ss_off = None, 0
ss = ''

# It's hacky that we keep a list of instruction blocks, but our heuristic for finding stack string COPY's
# isn't perfect so we'll just pick the larget one once we're done.
ss_insns = []

stack_strings = {
}

# *************************************
# TODO: Try just emulating the whole function and picking out strings from the resulting memory
# *************************************

while insn is not None and cont_fn == fn:
    pcode = insn.pcode

    for pc in pcode:
        # TODO: Change this so we're only emulating pcode we care about. Would work if varnode.getDef()
        #       worked outside the context of the decompiler. Meh.
        output = pc.output
        value = get_pcode_value(pc)

        if output is not None and type(output) != str:
            set_varnode_value(output, value)

        if pc.opcode == PcodeOp.STORE:
            dst = get_varnode_value(pc.getInput(1))
            src = get_varnode_value(pc.getInput(2))

            if src is None or dst is None or not found_ss or (type(src) != str and src > 0):
                clear_varnodes()
                continue

            if src == 0:
                src = '\x00'

            reg, off = None, 0

            try:
                if '+' in dst:
                    reg, off = dst.split('+')
                    off = int(off)
                elif '-' in dst:
                    reg, off = dst.split('-')
                    off = int(off)
                    off = -off
                else:
                    reg = dst
                    off = 0
            except ValueError:
                clear_varnodes()
                continue

            ss_insns = merge_insns(ss_insns, insn)

            if ss_reg is None:
                ss_reg = reg
                ss_off = off
                ss = src
            elif abs(ss_off + len(ss) - off) <= len(src) or abs(ss_off - off) <= len(src):
                ss = merge(ss, src, ss_off, off)
                ss_off = min(ss_off, off)
            else:
                clear_varnodes()
                continue

            if '\x00' in ss:
                if len(ss) > 1:
                    max_s, max_e = 0, 0

                    for s, e in ss_insns:
                        if e-s > max_s-max_e:
                            max_s, max_e = s, e

                    stack_strings[ss] = {
                        'start': max_s,
                        'end': max_e,
                        'reg': ss_reg,
                        'off': ss_off
                    }

                found_ss = False
                ss_reg = None
                ss_off = 0
                ss = ''
                ss_insns = []
                clear_varnodes()

        elif pc.opcode == PcodeOp.COPY:
            inpt = pc.getInput(0)

            lb = 4
            if found_ss:
                lb = 2

            if inpt.size < lb or inpt.getAddress().addressSpace.name != 'const':
                continue

            bs = vnode2bytes(inpt)
            if bs is None:
                continue

            nprintable = len([b for b in bs if b in string.printable])
            if nprintable / float(len(bs)) < 0.5:
                continue

            if len(bs) < inpt.size:
                bs += '\x00' * (inpt.size - len(bs))

            # Now that we've passed all the prerequisite checks, assume that we've found a stack string
            found_ss = True

            if len(ss_insns) == 0:
                ss_insns = [(insn.address.offset, insn.address.offset + insn.length)]
            else:
                ss_insns = merge_insns(ss_insns, insn)

            # Put our string into its address space
            output = pc.output
            set_varnode_value(output, bs)

    insn = insn.next
    if insn is not None:
        cont_fn = fp.getFunctionContaining(insn.address)


#strcpy = fp.getSymbols('_strcpy', None)
strcpy = fp.getFunctionAt(fp.toAddr(0x10133f4ba))

#if len(strcpy) == 0:
if strcpy is None:
    print('Couldn\'t find strcpy')
    exit()

#strcpy = strcpy[0]
strcpy_addr = strcpy.entryPoint

from ghidra.program.model.symbol import SourceType
from ghidra.program.model.data import PointerDataType, CharDataType
from ghidra.program.model.listing import ParameterImpl
from ghidra.program.model.listing.Function import FunctionUpdateType
from ghidra.program.model.lang import PrototypeModel

char_dt = CharDataType()
char_ptr_dt = PointerDataType(char_dt)

calling_conv = cp.functionManager.defaultCallingConvention

new_params = []

for dt, name in [(char_ptr_dt, 'dst'), (char_ptr_dt, 'src')]:
    arg_loc = calling_conv.getNextArgLocation(new_params, dt, cp)
    new_params.append(ParameterImpl(name, dt, arg_loc, cp, SourceType.USER_DEFINED))

strcpy = fp.getFunctionAt(strcpy_addr)
strcpy.replaceParameters(new_params, FunctionUpdateType.CUSTOM_STORAGE, True, SourceType.USER_DEFINED)
strcpy.setReturnType(char_ptr_dt, SourceType.USER_DEFINED)

for ss, ss_info in stack_strings.items():
    asm = generate_asm(ss, ss_info['reg'], ss_info['off'], strcpy_addr)
    blocks = get_load_bytes(asm, ss_info['start'])

    max_nb = ss_info['end'] - ss_info['start'] - len(ss)
    nb = sum([len(block[1]) for block in blocks])

    if nb > max_nb:
        # this is suuuuper hacky but if we don't have enough bytes, search the instruction before
        # our stack string moving block since it might be moving a null-terminator.
        #
        # I just saw this in one of the cases and is super specific. What is really needed is a shorter
        # way to strcpy.
        insn = fp.getInstructionAt(fp.toAddr(blocks[0][0])).previous
        pcode = insn.pcode
        
        if pcode[-1].opcode != PcodeOp.STORE:
            print('Can\'t deoptimize %s' % ss)
            continue

        # emulate all the pcode
        for pc in pcode:
            output = pc.output
            value = get_pcode_value(pc)

            if output is not None and type(output) != str:
                set_varnode_value(output, value)

            # this mean's that we've accessed a register. hopefully it's out stack string register
            if type(value) == str:
                reg, off = None, 0

                try:
                    if '+' in dst:
                        reg, off = dst.split('+')
                        off = int(off)
                    elif '-' in dst:
                        reg, off = dst.split('-')
                        off = int(off)
                        off = -off
                    else:
                        reg = dst
                        off = 0
                except ValueError:
                    continue

                overlap = get_intersection(ss, '', ss_info['off'], off)
                if overlap >= 0:
                    # this means that we've written to an overlapping region from our ss register
                    # relocate all of our blocks backwards
                    ss_info['start'] -= insn.length
                    blocks = get_load_bytes(asm, ss_info['start'])

                    max_nb = ss_info['end'] - ss_info['start'] - len(ss)
                    nb = sum([len(block[1]) for block in blocks])

                    if nb > max_nb:
                        print('Couldn\'t deoptimize %s' % ss)
                        continue

    if nb < max_nb:
        # fill the rest with nops
        blocks[1] = (blocks[1][0], blocks[1][1] + ([0x90] * (max_nb - nb)))

    print(ss)

    for off, bs in blocks:
        patch(bs, off)

    fp.clearListing(fp.toAddr(blocks[0][0] + len(blocks[0][1])), fp.toAddr(blocks[0][0] + len(blocks[0][1]) + len(ss)))
    cp.memory.setBytes(fp.toAddr(blocks[0][0] + len(blocks[0][1])), ss.encode('utf-8'))

    fp.createAsciiString(fp.toAddr(blocks[0][0] + len(blocks[0][1])))
    fp.disassemble(fp.toAddr(blocks[0][0]))

