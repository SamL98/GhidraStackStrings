from ghidra.program.model.pcode import PcodeOp, VarnodeTranslator
from ghidra.program.model.address import GenericAddress
from ghidra.program.flatapi import FlatProgramAPI

import binascii
import math
import struct as st

from __main__ import currentProgram

BINARY_PCODE_OPS = [PcodeOp.INT_ADD, PcodeOp.PTRSUB, PcodeOp.INT_SUB, PcodeOp.INT_MULT]

space_ram = None
space_uniq = None

cp = currentProgram
fp = FlatProgramAPI(cp)

name2space = {
    'register': {},
    'unique': {}
}

def get_value(data, signed=False):
    '''
    Wrapper around `struck.unpack` with different options on size and whether
    to interpret at signed.
    '''

    # Get the struct format based on size and signed
    endy_str = ['<', '>'][cp.language.isBigEndian()]
    fmt = endy_str + ['B', 'H', 'I', 'Q', 'QQ'][int(math.log(len(data), 2))]

    if signed:
        fmt = fmt.lower()

    # Finally, interpret the data
    data = st.unpack(fmt, data)[0]
    return data

def is_offset_in_current_program(off):
    '''
    Return whether or not `off` is in a defined memory region.
    '''
    for block in cp.memory.blocks:
        if block.start.offset <= off <= block.end.offset:
            return True
    return False

def is_address_in_current_program(addr):
    '''
    Return whether or not `addr` is in a defined memory region.
    '''
    return is_offset_in_current_program(addr.offset)

def get_value_from_addr(addr, size):
    '''
    Dereference an address in the current program.
    '''
    if not isinstance(addr, GenericAddress): addr = fp.toAddr(addr)
    return get_value(fp.getBytes(addr, size))

def get_pcode_value(pcode):
    '''
    Get the value of a pcode operation. Will recursively call `get_varnode_value` on the
    operation's operands.
    '''

    # Something might've gone wrong while backtracking (e.g. an unimplemented opcode)
    # so pcode could be None.

    if pcode is None:
        return None

    opcode = pcode.getOpcode()

    if opcode in BINARY_PCODE_OPS:
        op1 = get_varnode_value(pcode.getInput(0))
        op2 = get_varnode_value(pcode.getInput(1))

        if op1 is None or op2 is None:
            return None

        # TODO: change this !
        cast_to_str = False

        if type(op1) == unicode or type(op2) == unicode or type(op1) == str or type(op2) == str:
            op1 = str(op1)
            op2 = str(op2)
            cast_to_str = True

        if opcode == PcodeOp.INT_ADD or opcode == PcodeOp.PTRSUB:
            if cast_to_str:
                if '-' in op2:
                    return op1 + op2
                else:
                    return '%s+%s' % (op1, op2)
            return op1 + op2

        elif opcode == PcodeOp.INT_MULT:
            if cast_to_str:
                return '%s*%s' % (op1, op2)
            return op1 * op2

        elif opcode == PcodeOp.INT_SUB:
            if cast_to_str:
                return '%s-%s' % (op1, op2)
            return op1 - op2

    elif opcode == PcodeOp.PTRADD:
        op1 = get_varnode_value(pcode.getInput(0))
        op2 = get_varnode_value(pcode.getInput(1))
        op3 = get_varnode_value(pcode.getInput(2))

        if op1 is None or op2 is None or op3 is None:
            return None

        return op1 + op2 * op3

    elif opcode == PcodeOp.INT_2COMP:
        op = get_varnode_value(pcode.getInput(0))

        if op is None:
            return None

        return -op

    elif opcode == PcodeOp.COPY or opcode == PcodeOp.CAST:
        return get_varnode_value(pcode.getInput(0))

    elif opcode == PcodeOp.INDIRECT:
        # TODO: Figure out what exactly the indirect operator means and how to deal with it more precisely
        return get_varnode_value(pcode.getInput(0))

    elif opcode == PcodeOp.MULTIEQUAL:
        # TODO: Handle multiequal for actual multiple-possible values.
        #
        # Currently, this case is just meant to handle when Ghidra produces a Pcode op like:
        #       v1 = MULTIEQUAL(v1, v1)
        # for some reason. In this case, it's just the identity.
        op1 = pcode.getInput(0)

        for i in range(1, pcode.numInputs):
            opi = pcode.getInput(i)

            if op1.space != opi.space or op1.offset != opi.offset or op1.size != opi.size:
                print('Unhandled multiequal on differing inputs: %s' % pcode)
                return None

        return get_varnode_value(op1)

    elif opcode == PcodeOp.LOAD:
        off = get_varnode_value(pcode.getInput(1))
        if off is None:
            return None

        addr = fp.toAddr(off)
        if addr is None:
            return None

        space = pcode.getInput(0).offset

        # The offset of the space input specifies the address space to load from.
        # Right now, we're only handling loads from RAM

        if space_ram is not None and space == space_ram:
            return get_value_from_addr(addr, pcode.output.size)
        else:
            #print('Unhandled load space %d for pcode %s' % (space, pcode))
            return None

    #print('Unhandled pcode opcode %s pcode %s' % (pcode.getMnemonic(opcode), pcode))
    return None


def vnode2bytes(vnode):
    offset = vnode.offset

    if len(hex(offset)) % 2 == 0:
        return None

    return binascii.unhexlify(hex(offset)[2:-1])[::-1]


def get_varnode_value(varnode):
    space_name = varnode.getAddress().addressSpace.name
    offset = varnode.offset
    addr = fp.toAddr(offset)

    global space_ram
    if space_ram is None and space_name == 'ram':
        space_ram = varnode.space

    global space_uniq
    if space_uniq is None and space_name == 'unique':
        space_uniq = varnode.space

    if space_name == 'const':
        size = varnode.size
        return offset
    
    elif space_name == 'ram':
        if is_address_in_current_program(addr):
            return get_value_from_addr(addr, varnode.size)
        return None

    if space_name in name2space and offset in name2space[space_name]:
        return name2space[space_name][offset]

    if space_name == 'register':
        translator = VarnodeTranslator(cp)
        reg = translator.getRegister(varnode)
        if reg is not None:
            return reg.name

    else:
        # NOTE: It looks like definition is always null without the decompiler? Investigate, Sam. Just kidding, I know
        # you won't.
        defn = varnode.getDef()
        return get_pcode_value(defn)


def set_varnode_value(varnode, value):
    space_name = varnode.getAddress().addressSpace.name
    if space_name not in name2space:
        return

    space = name2space[space_name]
    offset = varnode.offset
    space[offset] = value


def is_varnode_relevant(varnode):
    space_name = varnode.getAddress().addressSpace.name
    if space_name not in name2space:
        return False

    space = name2space[space_name]
    offset = varnode.offset
    return offset in space


def clear_varnodes():
    for space_name in name2space.keys():
        name2space[space_name] = {}

