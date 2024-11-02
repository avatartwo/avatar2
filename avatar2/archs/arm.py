from capstone import *
from keystone.keystone_const import *
from unicorn import *
from unicorn.arm_const import *
from .architecture import Architecture
import avatar2

from avatar2.installer.config import QEMU, QEMU_AARCH64, PANDA, OPENOCD, GDB_ARM, GDB_AARCH64, GDB_MULTI


class ARM(Architecture):

    get_qemu_executable = Architecture.resolve(QEMU)
    get_panda_executable = Architecture.resolve(PANDA)
    get_gdb_executable = Architecture.resolve(GDB_MULTI)
    get_oocd_executable = Architecture.resolve(OPENOCD)

    qemu_name = 'arm'
    gdb_name = 'arm'
    # Based on gdb profile
    registers = {'r0': 0, 'r1': 1, 'r2': 2, 'r3': 3, 'r4': 4, 'r5': 5, 'r6': 6,
                 'r7': 7, 'r8': 8, 'r9': 9, 'r10': 10, 'r11': 11, 'r12': 12, 'ip': 12,
                 'sp': 13, 'lr': 14, 'pc': 15, 'cpsr': 25,
                 }
    unicorn_registers = {'r0': UC_ARM_REG_R0, 'r1': UC_ARM_REG_R1, 'r2': UC_ARM_REG_R2,
                         'r3': UC_ARM_REG_R3, 'r4': UC_ARM_REG_R4, 'r5': UC_ARM_REG_R5,
                         'r6': UC_ARM_REG_R6, 'r7': UC_ARM_REG_R7, 'r8': UC_ARM_REG_R8,
                         'r9': UC_ARM_REG_R9, 'r10': UC_ARM_REG_R10, 'r11': UC_ARM_REG_R11,
                         'r12': UC_ARM_REG_R12, 'sp': UC_ARM_REG_SP, 'lr': UC_ARM_REG_LR,
                         'pc': UC_ARM_REG_PC, 'cpsr': UC_ARM_REG_CPSR}
    pc_name = 'pc'
    sr_name = 'cpsr'
    unemulated_instructions = ['mcr', 'mrc']
    capstone_arch = CS_ARCH_ARM
    capstone_mode = CS_MODE_LITTLE_ENDIAN
    keystone_arch = KS_ARCH_ARM
    keystone_mode = KS_MODE_ARM
    unicorn_arch = UC_ARCH_ARM
    unicorn_mode = UC_MODE_ARM
    
class AARCH64(Architecture):

    get_qemu_executable = Architecture.resolve(QEMU_AARCH64)
    #get_panda_executable = Architecture.resolve(PANDA)
    get_gdb_executable  = Architecture.resolve(GDB_AARCH64)
    #get_oocd_executable = Architecture.resolve(OPENOCD)



    qemu_name = 'aarch64'
    gdb_name = 'aarch64'

    # note that many of these registers are read-only
    # registers that may only be written to using msr can not be written from gdb
    registers = {'x0': 0, 'x1': 1, 'x2': 2, 'x3': 3, 'x4': 4, 'x5': 5, 'x6': 6,
                 'x7': 7, 'x8': 8, 'x9': 9, 'x10': 10, 'x11': 11, 'x12': 12,
                 'x13': 13, 'x14': 14, 'x15': 15, 'x16': 16, 'x17': 17, 'x18': 18,
                 'x19': 19, 'x20': 20, 'x21': 21, 'x22': 22, 'x23': 23, 'x24': 24,
                 'x25': 25, 'x26': 26, 'x27': 27, 'x28': 28, 'x29': 29, 'lr': 30,
                 'sp': 31, 'pc': 32, 'cpsr': 33, 'fpsr': 66, 'fpcr': 67,
                 'MVFR6_EL1_RESERVED': 68, 'ESR_EL2': 69, 'MVFR7_EL1_RESERVED': 70, 'TPIDR_EL3': 71, 'MAIR_EL3': 72,
                 'ID_AA64PFR1_EL1': 73, 'ID_AA64PFR2_EL1_RESERVED': 74, 'AFSR0_EL3': 75,
                 'ID_AA64PFR3_EL1_RESERVED': 76, 'SCTLR': 77, 'AFSR1_EL3': 78, 'ID_AA64ZFR0_EL1': 79, 'CNTKCTL': 80,
                 'DACR32_EL2': 81, 'ID_AA64PFR5_EL1_RESERVED': 82, 'CPACR': 83, 'ID_AA64PFR6_EL1_RESERVED': 84,
                 'FPEXC32_EL2': 85, 'ACTLR_EL1': 86, 'ID_AA64PFR7_EL1_RESERVED': 87, 'ID_AA64DFR0_EL1': 88,
                 'AMAIR_EL3': 89, 'ID_AA64DFR1_EL1': 90, 'ID_AA64DFR2_EL1_RESERVED': 91, 'ESR_EL3': 92,
                 'ID_AA64DFR3_EL1_RESERVED': 93, 'ID_AA64AFR0_EL1': 94, 'ID_AA64AFR1_EL1': 95,
                 'ID_AA64AFR2_EL1_RESERVED': 96, 'CNTFRQ_EL0': 97, 'ID_AA64AFR3_EL1_RESERVED': 98, 'SPSR_EL1': 99,
                 'ID_AA64ISAR0_EL1': 100, 'DBGBVR': 197, 'ELR_EL1': 102, 'ID_AA64ISAR1_EL1': 103, 'FAR_EL2': 104,
                 'PMEVTYPER0_EL0': 105, 'DBGBCR': 199, 'ID_AA64ISAR2_EL1_RESERVED': 107, 'PMEVTYPER1_EL0': 108,
                 'DBGWVR': 170, 'ID_AA64ISAR3_EL1_RESERVED': 110, 'DBGWCR': 173, 'PMEVTYPER2_EL0': 112,
                 'ID_AA64ISAR4_EL1_RESERVED': 113, 'PMEVTYPER3_EL0': 114, 'MDCCSR_EL0': 115,
                 'ID_AA64ISAR5_EL1_RESERVED': 116, 'HPFAR_EL2': 117, 'ID_AA64ISAR6_EL1_RESERVED': 118,
                 'ID_AA64ISAR7_EL1_RESERVED': 119, 'CNTVOFF_EL2': 120, 'SP_EL0': 121, 'ID_AA64MMFR0_EL1': 122,
                 'ID_AA64MMFR1_EL1': 124, 'ID_AA64MMFR2_EL1': 126, 'PMINTENSET_EL1': 127,
                 'ID_AA64MMFR3_EL1_RESERVED': 129, 'SCTLR_EL2': 130, 'ID_AA64MMFR4_EL1_RESERVED': 132,
                 'PMCNTENSET_EL0': 133, 'CNTHCTL_EL2': 134, 'PMCR_EL0': 135, 'ID_AA64MMFR5_EL1_RESERVED': 136,
                 'PMCNTENCLR_EL0': 137, 'FAR_EL3': 138, 'ID_AA64MMFR6_EL1_RESERVED': 139, 'ACTLR_EL2': 140,
                 'PMOVSCLR_EL0': 141, 'MDSCR_EL1': 142, 'ID_AA64MMFR7_EL1_RESERVED': 143, 'CNTP_CTL_EL0': 144,
                 'PMSELR_EL0': 145, 'PMCEID1_EL0': 148, 'PMCEID0_EL0': 149, 'HCR_EL2': 151, 'PMCCNTR_EL0': 152,
                 'CNTP_CVAL_EL0': 153, 'MDCR_EL2': 155, 'CNTHP_TVAL_EL2': 156, 'CPTR_EL2': 157, 'CNTHP_CTL_EL2': 158,
                 'L2ACTLR': 159, 'HSTR_EL2': 160, 'TTBR0_EL1': 161, 'CNTHP_CVAL_EL2': 162, 'SCTLR_EL3': 163,
                 'TTBR1_EL1': 164, 'TCR_EL1': 165, 'HACR_EL2': 168, 'VBAR_EL2': 169, 'PMUSERENR_EL0': 171,
                 'CNTV_CTL_EL0': 172, 'VBAR': 174, 'ACTLR_EL3': 175, 'CNTV_CVAL_EL0': 176, 'PMOVSSET_EL0': 177,
                 'SCR_EL3': 178, 'SP_EL1': 179, 'MDRAR_EL1': 180, 'SDER32_EL3': 181, 'PMCCFILTR_EL0': 182,
                 'CPTR_EL3': 184, 'SPSR_EL3': 186, 'ELR_EL3': 187, 'CPUACTLR_EL1': 188, 'CPUECTLR_EL1': 189,
                 'VBAR_EL3': 190, 'CONTEXTIDR_EL1': 191, 'CNTPS_CTL_EL1': 192, 'CPUMERRSR_EL1': 193, 'RVBAR_EL3': 194,
                 'CNTPS_CVAL_EL1': 195, 'L2MERRSR_EL1': 196, 'MAIR_EL1': 198, 'TPIDR_EL1': 200, 'AFSR0_EL1': 201,
                 'OSLSR_EL1': 202, 'AFSR1_EL1': 203, 'PAR_EL1': 204, 'CBAR_EL1': 205, 'TTBR0_EL2': 206,
                 'SPSR_IRQ': 207, 'MDCR_EL3': 208, 'TCR_EL2': 209, 'SPSR_ABT': 210, 'SPSR_UND': 211, 'FPCR': 212,
                 'AMAIR0': 213, 'FPSR': 214, 'SPSR_FIQ': 215, 'ESR_EL1': 216, 'REVIDR_EL1': 217, 'CLIDR': 218,
                 'ID_PFR0': 219, 'VTTBR_EL2': 220, 'ID_DFR0': 221, 'ID_AFR0': 222, 'VTCR_EL2': 223, 'ID_MMFR0': 224,
                 'CSSELR': 225, 'ID_MMFR1': 226, 'TPIDR_EL0': 227, 'AIDR': 228, 'TTBR0_EL3': 229, 'ID_MMFR2': 230,
                 'TPIDRRO_EL0': 231, 'ID_MMFR3': 232, 'IFSR32_EL2': 233, 'TCR_EL3': 234, 'ID_ISAR0': 235,
                 'ID_ISAR1': 236, 'PMEVCNTR0_EL0': 237, 'ID_ISAR2': 238, 'PMEVCNTR1_EL0': 239, 'ID_ISAR3': 240,
                 'CTR_EL0': 241, 'TPIDR_EL2': 242, 'PMEVCNTR2_EL0': 243, 'ID_ISAR4': 244, 'PMEVCNTR3_EL0': 245,
                 'ID_ISAR5': 246, 'MAIR_EL2': 247, 'ID_MMFR4': 248, 'AFSR0_EL2': 249, 'ID_ISAR6': 250,
                 'AFSR1_EL2': 251, 'L2CTLR_EL1': 252, 'VPIDR_EL2': 253, 'MVFR0_EL1': 254, 'L2ECTLR_EL1': 255,
                 'FAR_EL1': 256, 'MVFR1_EL1': 257, 'MVFR2_EL1': 258, 'MVFR3_EL1_RESERVED': 259,
                 'MVFR4_EL1_RESERVED': 260, 'AMAIR_EL2': 261, 'MVFR5_EL1_RESERVED': 262}

    """unicorn_registers = {'r0': UC_ARM_REG_R0, 'r1': UC_ARM_REG_R1, 'r2': UC_ARM_REG_R2,
                         'r3': UC_ARM_REG_R3, 'r4': UC_ARM_REG_R4, 'r5': UC_ARM_REG_R5,
                         'r6': UC_ARM_REG_R6, 'r7': UC_ARM_REG_R7, 'r8': UC_ARM_REG_R8,
                         'r9': UC_ARM_REG_R9, 'r10': UC_ARM_REG_R10, 'r11': UC_ARM_REG_R11,
                         'r12': UC_ARM_REG_R12, 'sp': UC_ARM_REG_SP, 'lr': UC_ARM_REG_LR,
                         'pc': UC_ARM_REG_PC, 'cpsr': UC_ARM_REG_CPSR}"""
    pc_name = 'pc'
    sr_name = 'cpsr'
    #unemulated_instructions = ['mcr', 'mrc']
    #capstone_arch = CS_ARCH_ARM
    #capstone_mode = CS_MODE_LITTLE_ENDIAN
    #keystone_arch = KS_ARCH_ARM
    #keystone_mode = KS_MODE_ARM
    #unicorn_arch = UC_ARCH_ARM
    #unicorn_mode = UC_MODE_ARM


class ARM_CORTEX_M3(ARM):
    cpu_model = 'cortex-m3'
    qemu_name = 'arm'
    gdb_name = 'arm'

    capstone_mode = CS_MODE_LITTLE_ENDIAN | CS_MODE_THUMB | CS_MODE_MCLASS
    keystone_arch = KS_ARCH_ARM
    keystone_mode = KS_MODE_LITTLE_ENDIAN | KS_MODE_THUMB
    unicorn_arch = UC_ARCH_ARM
    unicorn_mode = UC_MODE_LITTLE_ENDIAN | UC_MODE_THUMB
    sr_name = 'xpsr'
    # The xpsr register has different register numbers across QEmu and OpenOCD, so we make sure to read/write it only by name
    special_registers = {'xpsr': {'gdb_expression': "$xpsr", 'format': "{:d}"}}

    @staticmethod
    def register_write_cb(avatar, *args, **kwargs):

        if isinstance(kwargs['watched_target'],
                      avatar2.targets.qemu_target.QemuTarget):
            qemu = kwargs['watched_target']

            # xcps/cpsr encodes the thumbbit diffently accross different
            # ISA versions. Panda_target does not cleanly support cortex-m yet,
            # and hence uses the thumbbit as stored on other ARM versions.
            if isinstance(qemu, avatar2.targets.panda_target.PandaTarget):
                shiftval = 5
            else:
                shiftval = 24

            if args[0] == 'pc' or args[0] == 'cpsr':
                cpsr = qemu.protocols.registers.read_register('cpsr')
                if cpsr & 1 << shiftval:
                    return
                else:
                    cpsr |= 1 << shiftval
                    qemu.protocols.registers.write_register('cpsr', cpsr)

    @staticmethod
    def init(avatar):
        avatar.watchmen.add('TargetRegisterWrite', 'after',
                            ARM_CORTEX_M3.register_write_cb)

        pass



ARMV7M = [ARM_CORTEX_M3]


class ARMBE(ARM):
    qemu_name = 'armeb'
    capstone_mode = CS_MODE_BIG_ENDIAN
