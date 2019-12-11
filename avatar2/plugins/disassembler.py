from types import MethodType

from capstone import *


def disassemble(self, addr=None, insns=1,
                arch=None, mode=None, detail=False):
    """
    Main purpose of the disassembler plugin, it's used to disassemble
    instructions
    :param addr:   The address to start disassembling.
                   If not specified, the current pc is used
    :param insns:  The numbe of instructions to be disassembled
    :param arch:   The capstone-architecture to be used.
                   If not specified, it is retrieved from avatar.arch
    :param mode:   The capstone-mode to be used.
                   If not specified, it is retrieved from avatar.arch
    :param detail: Whether to enable detailed disassembly
    :returns:     A list with capstone instructions
    """

    arch = self._arch.capstone_arch if not arch else arch
    mode = self._arch.capstone_mode if not mode else mode
    addr = self.regs.pc if not addr else addr

    ret = []
    md = Cs(arch, mode)
    md.detail = detail

    disassembled = 0
    while disassembled < insns:
        code_len = 8 * insns
        code = self.read_memory(addr, 1, code_len, raw=True)

        for ins in md.disasm(code, addr):
            ret.append(ins)
            disassembled += 1
            if disassembled >= insns:
                break

        addr += code_len
    return ret


def disassemble_pretty(self, addr=None, insns=1,
                       arch=None, mode=None):
    """
    Wrapper around disassemble to return disassembled instructions as string.
    """

    ret = ""
    disas = self.disassemble(addr, insns, arch, mode)

    for i in disas:
        ret += "0x%x:\t%s\t%s\n" % (i.address, i.mnemonic, i.op_str)

    return ret


def target_added_callback(avatar, *args, **kwargs):
    target = kwargs['watched_return']
    target.disassemble = MethodType(disassemble, target)
    target.disassemble_pretty = MethodType(disassemble_pretty, target)


def load_plugin(avatar):
    avatar.watchmen.add_watchman('AddTarget', when='after',
                                 callback=target_added_callback)
    for target in avatar.targets.values():
        target.disassemble = MethodType(disassemble, target)
        target.disassemble_pretty = MethodType(disassemble_pretty, target)
