from template_utils import expand_template

import subprocess
import binascii


def assemble(insn, at=None):
    args = ['rasm2', '-a', 'x86', '-b', '64']

    if at is not None:
        args.extend(['-@', hex(at)])

    args.append(insn)
    out = subprocess.check_output(args).strip()

    return [ord(d) for d in binascii.unhexlify(out)]

def generate_patch(pc, strval, reg, off, strcpy):
    patch = []

    def _assemble(line):
        insnBytes = assemble(line)
        patch.extend(insnBytes)
        return len(insnBytes)

    expand_template(pc,
                    strval,
                    reg,
                    off,
                    strcpy,
                    size_cb=_assemble)

    return patch
