from ghidra.program.model.listing import ParameterImpl, FlowOverride
from ghidra.program.model.listing.Function import FunctionUpdateType
from ghidra.program.model.data import PointerDataType, CharDataType
from ghidra.program.model.lang import PrototypeModel, Register
from ghidra.program.model.block import BasicBlockModel
from ghidra.program.model.address import AddressSet
from ghidra.program.model.symbol import SourceType
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.program.model.scalar import Scalar
from ghidra.util.task import TaskMonitor

import struct as st
import atexit
import string
import math

from emulator_utils import *
from asm_utils import *


def getBasicBlocks(func):
    bbm = BasicBlockModel(currentProgram)
    buf = bbm.getCodeBlocksContaining(func.entryPoint, TaskMonitor.DUMMY)
    visited = set()
    blocks = []

    while len(buf) > 0:
        block = buf.pop(0)

        if block not in visited and getFunctionContaining(block.minAddress) == func:
            #print(block.minAddress)
            blocks.append(block)
            visited.add(block)

            iter = block.getDestinations(TaskMonitor.DUMMY)

            while iter.hasNext():
                buf.append(iter.next().destinationBlock)

    return blocks

class Buffer(object):
    def __init__(self, addr, size):
        self.start = addr
        self.end = addr.add(size)
        self.size = size
        self.reg = None
        self.off = 1000000
        self.write_start = 0xffffffffffffffff
        self.write_end = 0x0

class StackString(object):
    def __init__(self, value, reg, off, write_start, write_end):
        self.value = value
        self.reg = reg
        self.off = off
        self.write_start = write_start
        self.write_end = write_end

class Heap(object):
    def __init__(self, head):
        self.head = head

    def alloc(self, size):
        ptr = self.head
        self.head += size
        return ptr

def getStackStrings():
    func = getFunctionContaining(currentAddress)
    blocks = getBasicBlocks(func)

    heap = Heap(0x80000000)
    bufs = []
    stackStrings = []

    def handle_write(addr, size, val, pc, emu=None):
        #if sum([b in string.printable for b in val.decode('utf-8')]) / float(len(val)) < 0.5:
        #    return

        for buf in bufs:
            if buf.start <= addr and addr <= buf.end:
                buf.write_start = min(buf.write_start, pc)
                buf.write_end   = max(buf.write_end  , pc)

                insn = getInstructionAt(toAddr(pc))

                for i in range(insn.numOperands):
                    if insn.getOperandRefType(i).isWrite():
                        objs = insn.getOpObjects(i)

                        for obj in objs:
                            if isinstance(obj, Register):
                                buf.reg = obj
                            elif isinstance(obj, Scalar):
                                buf.off = min(buf.off, obj.unsignedValue)

    def malloc(size, *args, **kwargs):
        ptr = heap.alloc(size)

        if size > 0:
            addr = toAddr(ptr)
            bufs.append(Buffer(addr, size))

            if 'emu' in kwargs:
                #print('Allocated 0x%x bytes to %s @ %s' % (size, addr, toAddr(kwargs['emu'].get_pc())))
                watch(addr, size, handler=handle_write, emu=kwargs['emu'])

        return ptr

    for block in blocks:
        bufs = []

        #print('Emulating block %s - %s' % (block.minAddress, block.maxAddress))
        cpuState = emulate(block.minAddress,
                           block.maxAddress,
                           hooks={'operator.new': malloc},
                           skip_calls=True)

        for buf in bufs:
            try:
                contents = cpuState.read(buf.start, buf.size).decode('utf-8')
            except UnicodeDecodeError:
                continue

            for i, b in enumerate(contents):
                if b == u'\x00':
                    value = contents[:i+1]

                    if len(value) > 8:
                        # Fixup the write start assuming the instructions are contiguous.
                        buf.write_start = getInstructionBefore(toAddr(buf.write_start)).address.offset
                        buf.write_end += getInstructionAt(toAddr(buf.write_end)).length

                        print('Found stack string "%s" written to (%s, 0x%x) from %s - %s' % (value, buf.reg, buf.off, toAddr(buf.write_start), toAddr(buf.write_end)))
                        stackString = StackString(value, buf.reg, buf.off, buf.write_start, buf.write_end)
                        stackStrings.append(stackString)

                if b not in string.printable:
                    break

    return stackStrings


namespace_man = currentProgram.namespaceManager
strcpy = None

for namespace in namespace_man.getNamespacesOverlapping(AddressSet(currentProgram.minAddress, currentProgram.maxAddress)):
    if 'strcpy' in namespace.name:
        strcpy = getFunctionAt(namespace.body.minAddress)
        break

if strcpy is None:
    print('Couldn\'t find strcpy')
    exit()

char_dt = CharDataType()
char_ptr_dt = PointerDataType(char_dt)

cc = currentProgram.functionManager.defaultCallingConvention
new_params = []

for dt, name in [(char_ptr_dt, 'dst'), (char_ptr_dt, 'src')]:
    arg_loc = cc.getNextArgLocation(new_params, dt, currentProgram)
    new_params.append(ParameterImpl(name, dt, arg_loc, currentProgram, SourceType.USER_DEFINED))

strcpy.replaceParameters(new_params, FunctionUpdateType.CUSTOM_STORAGE, True, SourceType.USER_DEFINED)
strcpy.setReturnType(char_ptr_dt, SourceType.USER_DEFINED)

for ss in getStackStrings():
    patch = generate_patch(ss.write_start,
                           ss.value,
                           ss.reg.name,
                           ss.off,
                           strcpy.entryPoint.offset)

    freeSpace = ss.write_end - ss.write_start

    if len(patch) > freeSpace:
        print('Couldn\'t deoptimize %s, %d bytes short' % (ss.value[:-1], len(patch) - freeSpace))
        continue

    # fill the rest with nops
    patch += [0x90] * (freeSpace - len(patch))

    #print('Deoptimizing "%s"' % ss.value[:-1])

    clearListing(toAddr(ss.write_start), toAddr(ss.write_end))
    currentProgram.memory.setBytes(toAddr(ss.write_start), bytes(bytearray(patch)))
    disassemble(toAddr(ss.write_start))

    # Do some final fixups for the decompiler.
    insn = getInstructionAt(toAddr(ss.write_start))

    while insn is not None:
        if insn.flowType.isCall():
            insn.setFlowOverride(FlowOverride.BRANCH)

            stringStart = insn.address.add(insn.length)
            clearListing(stringStart, stringStart.add(len(ss.value) - 1))
            createAsciiString(stringStart)

            break

        insn = insn.next

