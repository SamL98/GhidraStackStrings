from ghidra.program.model.address import Address, AddressSet
from ghidra.app.emulator import EmulatorHelper
from ghidra.util.task import TaskMonitor
from __main__ import *

import struct as st


class Emulator(object):
    def __init__(self):
        self.emu = EmulatorHelper(currentProgram)
        self.emu.enableMemoryWriteTracking(True)

        self.pc_reg = self.emu.getPCRegister()
        self.sp_reg = self.emu.getStackPointerRegister()

        self.watchpoints = {}
        self.writeSet = AddressSet()

    def get_pc(self):
        return self.emu.readRegister(self.pc_reg)

    def set_pc(self, val):
        if isinstance(val, Address):
            val = val.offset
        self.emu.writeRegister(self.pc_reg, val)

    def set_sp(self, val):
        if isinstance(val, Address):
            val = val.offset
        self.emu.writeRegister(self.sp_reg, val)

    def read(self, addr, size):
        return bytearray(self.emu.readMemory(addr, size))

    def step(self, skip_calls):
        pc = toAddr(self.get_pc())

        if skip_calls:
            insn = getInstructionAt(pc)

            if insn is None:
                print('Instruction is none @ %s' % pc)
                exit()

            if insn.flowType.isCall():
                new_pc = pc.add(insn.length)
                self.set_pc(new_pc)
                return

        prev_pc = pc
        self.emu.step(TaskMonitor.DUMMY)

        # This isn't exactly correct since we can only call a watchpoint on an address once but it should work ok.
        fullWriteSet = self.emu.trackedMemoryWriteSet

        #for addrSet in fullWriteSet.subtract(self.writeSet):
        for addrSet in fullWriteSet:
            size = addrSet.maxAddress.subtract(addrSet.minAddress)

            if addrSet.minAddress.isMemoryAddress() and size > 0:
                calledHandles = []

                for addr, handler in self.watchpoints.items():
                    if addr >= addrSet.minAddress and addr <= addrSet.maxAddress:
                        val = self.read(addr, 1)
                        handler(addr, 1, val, prev_pc.offset, emu=self)
                        calledHandles.append(addr)

                for addr in calledHandles:
                    del self.watchpoints[addr]

        self.writeSet = self.writeSet.union(fullWriteSet)

    def watch(self, addr, size, handler):
        for _ in range(size):
            self.watchpoints[addr] = handler
            addr = addr.add(1)

    def readVar(self, var):
        if var.isStackVariable():
            stackOff = var.getStackOfset()
            return self.emu.readStackValue(stackOff, var.length, False)

        elif var.isRegisterVariable():
            reg = var.getRegister()
            return self.emu.readRegister(reg)

    def writeVar(self, var, val):
        if var.isStackVariable():
            stackOff = var.getStackOfset()
            return self.emu.writeStackValue(stackOff, var.length, val)

        elif var.isRegisterVariable():
            reg = var.getRegister()
            return self.emu.writeRegister(reg, val)


def call_hook(pc, handler, emu):
    args = []
    func = getFunctionAt(pc)

    if func is not None:
        args = [emu.readVar(param) for param in func.parameters]

    retval = handler(*args, emu=emu)

    if retval is not None and func.getReturn() is not None:
        emu.writeVar(func.getReturn(), retval)

def emulate(startAddr, endAddr, hooks=None, skip_calls=False):
    actual_hooks = {}

    for key, handler in hooks.items():
        if isinstance(key, (str, unicode)):
            keys = [func.entryPoint for func in getGlobalFunctions(key)]
        elif isinstance(key, (int, long)):
            keys = [toAddr(key)]
        else:
            keys = [key]

        for key in keys:
            actual_hooks[key] = handler

    hooks = actual_hooks

    if getInstructionAt(endAddr) is None:
        endAddr = getInstructionBefore(endAddr).address

    emu = Emulator()
    emu.set_pc(startAddr)
    emu.set_sp(0xf0000000)

    prev_pc = None

    while emu.get_pc() != endAddr.offset and emu.get_pc() != prev_pc:
        pc = toAddr(emu.get_pc())

        if pc in hooks:
            call_hook(pc, hooks[pc], emu)

        for ref in getReferencesFrom(pc):
            if ref.referenceType.isCall():
                dest = ref.toAddress

                if dest in hooks:
                    call_hook(dest, hooks[dest], emu)

        prev_pc = pc.offset
        emu.step(skip_calls)

    return emu

def watch(addr, size, handler=None, emu=None):
    emu.watch(addr, size, handler)
