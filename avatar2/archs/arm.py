# from capstone import CS_ARCH_ARM, CS_MODE_LITTLE_ENDIAN, CS_MODE_BIG_ENDIAN

from capstone import *
from keystone import *
from .architecture import Architecture
import avatar2

from avatar2.installer.config import QEMU, PANDA, OPENOCD, GDB_ARM

class ARM(Architecture):

    get_qemu_executable = Architecture.resolve(QEMU)
    get_panda_executable = Architecture.resolve(PANDA)
    get_gdb_executable  = Architecture.resolve(GDB_ARM)
    get_oocd_executable = Architecture.resolve(OPENOCD)



    qemu_name = 'arm'
    gdb_name = 'arm'
    registers = {'r0': 0, 'r1': 1, 'r2': 2, 'r3': 3, 'r4': 4, 'r5': 5, 'r6': 6,
                 'r7': 7, 'r8': 8, 'r9': 9, 'r10': 10, 'r11': 11, 'r12': 12,
                 'sp': 13, 'lr': 14, 'pc': 15, 'cpsr': 25,
                 }
    sr_name = 'cpsr'
    unemulated_instructions = ['mcr', 'mrc']
    capstone_arch = CS_ARCH_ARM
    capstone_mode = CS_MODE_LITTLE_ENDIAN
    keystone_arch = KS_ARCH_ARM
    keystone_mode = KS_MODE_ARM


class ARM_CORTEX_M3(ARM):
    cpu_model = 'cortex-m3'
    qemu_name = 'arm'
    gdb_name = 'arm'

    capstone_arch = CS_ARCH_ARM
    capstone_mode = CS_MODE_LITTLE_ENDIAN | CS_MODE_THUMB | CS_MODE_MCLASS
    keystone_arch = KS_ARCH_ARM
    keystone_mode = KS_MODE_LITTLE_ENDIAN | KS_MODE_THUMB


    @staticmethod
    def register_write_cb(avatar, *args, **kwargs):
        if isinstance(kwargs['watched_target'],
                      avatar2.targets.qemu_target.QemuTarget):
            qemu = kwargs['watched_target']

            if args[0] == 'pc' or args[0] == 'cpsr':
                cpsr = qemu.read_register('cpsr')
                if cpsr & 0x20:
                    return
                else:
                    cpsr |= 0x20
                    qemu.write_register('cpsr', cpsr)

    @staticmethod
    def init(avatar):
        avatar.watchmen.add('TargetRegisterWrite', 'after',
                            ARM_CORTEX_M3.register_write_cb)

ARMV7M = ARM_CORTEX_M3


class ARMBE(ARM):
    qemu_name = 'armeb'
    capstone_mode = CS_MODE_BIG_ENDIAN
