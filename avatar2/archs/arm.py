from capstone import CS_ARCH_ARM, CS_MODE_LITTLE_ENDIAN, CS_MODE_BIG_ENDIAN

class ARM(object):
    qemu_name = 'arm'
    registers = {'r0': 0, 'r1': 1, 'r2': 2, 'r3': 3, 'r4': 4, 'r5': 5, 'r6': 6,
                'r7': 7, 'r8': 8, 'r9': 9, 'r10': 10, 'r11': 11, 'r12': 12,
                'sp': 13, 'lr': 14, 'pc': 15, 'cpsr': 25,
                }
    unemulated_instructions = ['mcr', 'mrc']
    capstone_arch = CS_ARCH_ARM
    capstone_mode = CS_MODE_LITTLE_ENDIAN

class ARMBE(ARM):
    qemu_name = 'armeb'
    capstone_mode = CS_MODE_BIG_ENDIAN
