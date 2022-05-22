STATE_ASM = 0
STATE_IF = 1
STATE_SKIPPING_IF = 2
STATE_SKIPPING_ELSE = 3

def rindex(str, c):
    return len(str) - str[::-1].index(c) - 1

class Parser(object):
    def __init__(self):
        self.state = STATE_ASM
        self.stack = []

        self.stateTable = {
            STATE_ASM:           self.asm_handleLine,
            STATE_IF:            self.if_handleLine,
            STATE_SKIPPING_IF:   self.skipping_if_handleLine,
            STATE_SKIPPING_ELSE: self.skipping_else_handleLine
        }

    def handle_if(self, line, strval, reg, off, strcpy):
        clause = line[line.index('(')+1:rindex(line, ')')]
        self.stack.append(self.state)

        if eval(clause):
            return STATE_IF, None
        else:
            return STATE_SKIPPING_IF, None

    def handle_endif(self, line, strval, reg, off, strcpy):
        prevState = self.stack.pop(-1)

        if len(self.stack) == 0:
            return STATE_ASM, None
        else:
            return prevState, None

    def asm_handleLine(self, line, strval, reg, off, strcpy):
        if line.startswith('@if'):
            return self.handle_if(line, strval, reg, off, strcpy)
        elif line.startswith('@endif'):
            return self.handle_endif(line, strval, reg, off, strcpy)
        else:
            return STATE_ASM, line

    def if_handleLine(self, line, strval, reg, off, strcpy):
        if line.startswith('@if'):
            return self.handle_if(line, strval, reg, off, strcpy)
        elif line.startswith('@else'):
            return STATE_SKIPPING_ELSE, None
        elif line.startswith('@endif'):
            return self.handle_endif(line, strval, reg, off, strcpy)
        else:
            return STATE_IF, line

    def skipping_if_handleLine(self, line, strval, reg, off, strcpy):
        if line.startswith('@if'):
            self.stack.append(self.state)
            return STATE_SKIPPING_IF, None
        elif line.startswith('@else'):
            return STATE_ASM, None
        elif line.startswith('@endif'):
            return self.handle_endif(line, strval, reg, off, strcpy)
        else:
            return STATE_SKIPPING_IF, None

    def skipping_else_handleLine(self, line, strval, reg, off, strcpy):
        if line.startswith('@if'):
            self.stack.append(self.state)
            return STATE_SKIPPING_ELSE, None
        elif line.startswith('@endif'):
            return self.handle_endif(line, strval, reg, off, strcpy)
        else:
            return STATE_SKIPPING_ELSE, None

    def handleLine(self, line, strval, reg, off, strcpy):
        if len(line) == 0:
            return None

        newState, line = self.stateTable[self.state](line, strval, reg, off, strcpy)
        self.state = newState
        return line


def expand_template(pc, strval, reg, off, strcpy, size_cb):
    lines = []
    parser = Parser()

    with open('patch_template.asm') as f:
        for line in f:
            line = line.strip()
            line = line.replace('${reg}', reg)
            line = line.replace('${off}', hex(off))
            line = line.replace('${str}', '\n'.join(['.byte %s' % hex(ord(b)) for b in strval]))
            line = line.replace('${strcpy}', hex(strcpy - pc))
            line = line.replace('${strlen_plus_5}', hex(len(strval) + 5))

            line = parser.handleLine(line, strval, reg, off, strcpy)

            if line is not None:
                lines.append(line)
                pc += size_cb(line)

    return lines
