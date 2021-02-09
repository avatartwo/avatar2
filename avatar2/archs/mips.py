from capstone import *
from keystone.keystone_const import *
from unicorn import *
from unicorn.mips_const import *
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

    unicorn_registers = {
        'zero': UC_MIPS_REG_0, 'at': UC_MIPS_REG_1, 'v0': UC_MIPS_REG_2,
        'v1': UC_MIPS_REG_3, 'a0': UC_MIPS_REG_4, 'a1': UC_MIPS_REG_5,
        'a2': UC_MIPS_REG_6, 'a3': UC_MIPS_REG_7, 't0': UC_MIPS_REG_8,
        't1': UC_MIPS_REG_9, 't2': UC_MIPS_REG_10, 't3': UC_MIPS_REG_11,
        't4': UC_MIPS_REG_12, 't5': UC_MIPS_REG_13, 't6': UC_MIPS_REG_14,
        't7': UC_MIPS_REG_15, 's0': UC_MIPS_REG_16, 's1': UC_MIPS_REG_17,
        's2': UC_MIPS_REG_18, 's3': UC_MIPS_REG_19, 's4': UC_MIPS_REG_20,
        's5': UC_MIPS_REG_21, 's6': UC_MIPS_REG_22, 's7': UC_MIPS_REG_23,
        't8': UC_MIPS_REG_24, 't9': UC_MIPS_REG_25, 'k0': UC_MIPS_REG_26,
        'k1': UC_MIPS_REG_27, 'gp': UC_MIPS_REG_28, 'sp': UC_MIPS_REG_29,
        'fp': UC_MIPS_REG_30, 'ra': UC_MIPS_REG_31, 'pc': UC_MIPS_REG_PC
        }

    pc_name = 'pc'
    sr_name = 'cpsr'

    capstone_arch = CS_ARCH_MIPS
    keystone_arch = KS_ARCH_MIPS

    unicorn_arch = UC_ARCH_MIPS
    unicorn_mode = UC_MODE_MIPS32


class MIPS_BE(MIPS32):

    endian = 'big'

    qemu_name = 'mips'
    gdb_name = 'mips'
    angr_name = 'mips'

    capstone_mode = CS_MODE_BIG_ENDIAN + CS_MODE_MIPS32
    keystone_mode = KS_MODE_BIG_ENDIAN + KS_MODE_MIPS32
    unicorn_mode = UC_MODE_BIG_ENDIAN | UC_MODE_THUMB


class MIPS_LE(MIPS32):

    endian = 'little'

    qemu_name = 'mipsel'
    gdb_name = 'mips'
    angr_name = 'mipsel'

    capstone_mode = CS_MODE_LITTLE_ENDIAN + CS_MODE_MIPS32
    keystone_mode = KS_MODE_LITTLE_ENDIAN + KS_MODE_MIPS32
    unicorn_mode = UC_MODE_LITTLE_ENDIAN | UC_MODE_THUMB



class MIPS_24KF(MIPS_BE):

    cpu_model = '24Kf'

