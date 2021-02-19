from types import MethodType

from keystone import *


def assemble(self, asmstr, addr=None,
                arch=None, mode=None):
    """
    Main purpose of the assembler plugin, it's used to assemble
    instructions
    :param addr:  The address to start disassembling.
                  If not specified, the current pc is used
    :param arch:  The keystone-architecture to be used.
    :param mode:  The keystone-mode to be used.
                  If not specified, it is retrieved from avatar.arch
    :returns:     Raw bytes
    """

    arch = self._arch.keystone_arch if not arch else arch
    mode = self._arch.keystone_mode if not mode else mode
    addr = self.regs.pc if not addr else addr

    md = Ks(arch, mode)
    bytelist = md.asm(asmstr, addr)[0]
    bytes_raw = bytes(bytelist)
    return bytes_raw

def inject_asm(self, asmstr, addr=None, arch=None, mode=None):
    """
    Assemble the string, and inject it into the target)
    """
    arch = self._arch.keystone_arch if not arch else arch
    mode = self._arch.keystone_mode if not mode else mode
    addr = self.regs.pc if not addr else addr

    md = Ks(arch, mode)
    bytelist = md.asm(asmstr, addr)[0]
    bytes_raw = bytes(bytelist)
    return self.write_memory(addr, 1, bytes_raw, len(bytes_raw), raw=True)

def target_added_callback(avatar, *args, **kwargs):
    target = kwargs['watched_return']
    target.assemble = MethodType(assemble, target)
    target.inject_asm = MethodType(inject_asm, target)


def load_plugin(avatar):
    avatar.watchmen.add_watchman('AddTarget', when='after',
                                 callback=target_added_callback)
    for target in avatar.targets.values():
        target.assemble = MethodType(assemble, target)
        target.inject_asm = MethodType(inject_asm, target)
