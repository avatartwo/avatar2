import logging
from types import MethodType

from keystone import *


def assemble(self, asmstr, addr=None, arch=None, mode=None):
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


def inject_asm(self, asmstr, addr=None, arch=None, mode=None, patch=None):
    """
    Assemble the string, and inject it into the targets' memory.

    :param asmstr: The assembly string to be assembled
    :param addr:   Optional address at which the assembly should be injected, defaults to `pc`
    :param arch:   Optional keystone-architecture to be used, defaults to architecture of target
    :param mode:   Optional keystone-mode to be used, defaults to mode of target
    :param patch:  Optional dictionary of address->bytes patches to be replaced in the assembled code
                    (eg. `patch={0x20001000: b'\xef\xf3\x05\x85'}`)

    :returns:      True if the injection was successful, False otherwise
    """
    arch = self._arch.keystone_arch if not arch else arch
    mode = self._arch.keystone_mode if not mode else mode
    addr = self.regs.pc if not addr else addr
    logging.getLogger('avatar').debug(f"Injecting assembly into address 0x{addr:8x}")

    md = Ks(arch, mode)
    bytelist = md.asm(asmstr, addr)[0]
    bytes_raw = bytes(bytelist)
    if patch is not None:
        for key in patch.keys():
            bytes_raw = bytes_raw[:key] + patch[key] + bytes_raw[key + len(patch[key]):]
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
