from capstone import *
from keystone.keystone_const import *
from .architecture import Architecture
import avatar2

from avatar2.installer.config import QEMU, PANDA, OPENOCD, GDB_MULTI


class MIPS32(Architecture):

    get_qemu_executable = Architecture.resolve(QEMU)
    get_panda_executable = Architecture.resolve(PANDA)
    get_gdb_executable  = Architecture.resolve(GDB_MULTI)
    get_oocd_executable = Architecture.resolve(OPENOCD)


    registers = {
        'zero': 0, 
        'at': 1, 
        'v0': 2, 'v1': 3, 
        'a0': 4, 'a1': 5, 'a2': 6, 'a3': 7, 
        't0': 8, 't1': 9, 't2': 10, 't3': 11, 't4': 12, 't5': 13, 't6': 14, 't7': 15, 
        's0': 16, 's1': 17, 's2': 18, 's3': 19, 's4': 20, 's5': 21, 's6': 22, 's7': 23, 
        't8': 24, 't9': 25, 
        'k0': 26, 'k1': 27,
        'gp': 28, 'sp': 29, 'fp': 30, 'ra': 31, 'pc': 32,
    }

    pc_name = 'pc'
    sr_name = 'cpsr'

    capstone_arch = CS_ARCH_MIPS
    keystone_arch = KS_ARCH_MIPS



class MIPS_BE(MIPS32):

    endian = 'big'

    qemu_name = 'mips'
    gdb_name = 'mips'
    angr_name = 'mips'

    capstone_mode = CS_MODE_BIG_ENDIAN + CS_MODE_MIPS32
    keystone_mode = KS_MODE_BIG_ENDIAN + KS_MODE_MIPS32


class MIPS_LE(MIPS32):

    endian = 'little'

    qemu_name = 'mipsel'
    gdb_name = 'mips'
    angr_name = 'mipsel'

    capstone_mode = CS_MODE_LITTLE_ENDIAN + CS_MODE_MIPS32
    keystone_mode = KS_MODE_LITTLE_ENDIAN + KS_MODE_MIPS32



class MIPS_24KF(MIPS_BE):

    cpu_model = '24Kf'

