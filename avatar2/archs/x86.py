from capstone import *

from .architecture import Architecture

from avatar2.installer.config import GDB_X86, OPENOCD

class X86(Architecture):

    get_gdb_executable  = Architecture.resolve(GDB_X86)
    get_oocd_executable = Architecture.resolve(OPENOCD)



    qemu_name = 'i386'
    gdb_name = 'i386'
    registers = {'eax': 0,
                 'ecx': 1,
                 'edx': 2,
                 'ebx': 3,
                 'esp': 4,
                 'ebp': 5,
                 'esi': 6,
                 'edi': 7,
                 'eip': 8,
                 'pc': 8,
                 'eflags': 9,
                 'cs': 10,
                 'ss': 11,
                 'ds': 12,
                 'es': 13,
                 'fs': 14,
                 'gs': 15, }

    special_registers = {
        #SSE
        'xmm0': {'format': '{{{:d}, {:d}, {:d}, {:d}}}',
                 'gdb_expression': '$xmm0.v4_int32',
                },
        'xmm1': {'format': '{{{:d}, {:d}, {:d}, {:d}}}',
                 'gdb_expression': '$xmm1.v4_int32',
                },
        'xmm2': {'format': '{{{:d}, {:d}, {:d}, {:d}}}',
                 'gdb_expression': '$xmm2.v4_int32',
                },
        'xmm3': {'format': '{{{:d}, {:d}, {:d}, {:d}}}',
                 'gdb_expression': '$xmm3.v4_int32',
                },
        'xmm4': {'format': '{{{:d}, {:d}, {:d}, {:d}}}',
                 'gdb_expression': '$xmm4.v4_int32',
                },
        'xmm5': {'format': '{{{:d}, {:d}, {:d}, {:d}}}',
                 'gdb_expression': '$xmm5.v4_int32',
                },
        'xmm6': {'format': '{{{:d}, {:d}, {:d}, {:d}}}',
                 'gdb_expression': '$xmm6.v4_int32',
                },
        'xmm7': {'format': '{{{:d}, {:d}, {:d}, {:d}}}',
                 'gdb_expression': '$xmm7.v4_int32',
                },
        'xmm8': {'format': '{{{:d}, {:d}, {:d}, {:d}}}',
                 'gdb_expression': '$xmm8.v4_int32',
                },
        'xmm9': {'format': '{{{:d}, {:d}, {:d}, {:d}}}',
                 'gdb_expression': '$xmm9.v4_int32',
                },
        'xmm10': {'format': '{{{:d}, {:d}, {:d}, {:d}}}',
                 'gdb_expression': '$xmm10.v4_int32',
                 },
        'xmm11': {'format': '{{{:d}, {:d}, {:d}, {:d}}}',
                 'gdb_expression': '$xmm11.v4_int32',
                 },
        'xmm12': {'format': '{{{:d}, {:d}, {:d}, {:d}}}',
                 'gdb_expression': '$xmm12.v4_int32',
                 },
        'xmm13': {'format': '{{{:d}, {:d}, {:d}, {:d}}}',
                 'gdb_expression': '$xmm13.v4_int32',
                 },
        'xmm14': {'format': '{{{:d}, {:d}, {:d}, {:d}}}',
                 'gdb_expression': '$xmm14.v4_int32',
                 },
        'xmm15': {'format': '{{{:d}, {:d}, {:d}, {:d}}}',
                 'gdb_expression': '$xmm15.v4_int32',
                 },
        #AVX
        'ymm0': {'format': '{{{:d}, {:d}, {:d}, {:d}, {:d}, {:d}, {:d}, {:d}}}',
                 'gdb_expression': '$ymm0.v8_int32',
                },
        'ymm1': {'format': '{{{:d}, {:d}, {:d}, {:d}, {:d}, {:d}, {:d}, {:d}}}',
                 'gdb_expression': '$ymm1.v8_int32',
                },
        'ymm2': {'format': '{{{:d}, {:d}, {:d}, {:d}, {:d}, {:d}, {:d}, {:d}}}',
                 'gdb_expression': '$ymm2.v8_int32',
                },
        'ymm3': {'format': '{{{:d}, {:d}, {:d}, {:d}, {:d}, {:d}, {:d}, {:d}}}',
                 'gdb_expression': '$ymm3.v8_int32',
                },
        'ymm4': {'format': '{{{:d}, {:d}, {:d}, {:d}, {:d}, {:d}, {:d}, {:d}}}',
                 'gdb_expression': '$ymm4.v8_int32',
                },
        'ymm5': {'format': '{{{:d}, {:d}, {:d}, {:d}, {:d}, {:d}, {:d}, {:d}}}',
                 'gdb_expression': '$ymm5.v8_int32',
                },
        'ymm6': {'format': '{{{:d}, {:d}, {:d}, {:d}, {:d}, {:d}, {:d}, {:d}}}',
                 'gdb_expression': '$ymm6.v8_int32',
                },
        'ymm7': {'format': '{{{:d}, {:d}, {:d}, {:d}, {:d}, {:d}, {:d}, {:d}}}',
                 'gdb_expression': '$ymm7.v8_int32',
                },
        'ymm8': {'format': '{{{:d}, {:d}, {:d}, {:d}, {:d}, {:d}, {:d}, {:d}}}',
                 'gdb_expression': '$ymm8.v8_int32',
                },
        'ymm9': {'format': '{{{:d}, {:d}, {:d}, {:d}, {:d}, {:d}, {:d}, {:d}}}',
                 'gdb_expression': '$ymm9.v8_int32',
                },
        'ymm10': {'format': '{{{:d}, {:d}, {:d}, {:d}, {:d}, {:d}, {:d}, {:d}}}',
                 'gdb_expression': '$ymm10.v8_int32',
                },
        'ymm11': {'format': '{{{:d}, {:d}, {:d}, {:d}, {:d}, {:d}, {:d}, {:d}}}',
                 'gdb_expression': '$ymm11.v8_int32',
                },
        'ymm12': {'format': '{{{:d}, {:d}, {:d}, {:d}, {:d}, {:d}, {:d}, {:d}}}',
                 'gdb_expression': '$ymm12.v8_int32',
                },
        'ymm13': {'format': '{{{:d}, {:d}, {:d}, {:d}, {:d}, {:d}, {:d}, {:d}}}',
                 'gdb_expression': '$ymm13.v8_int32',
                },
        'ymm14': {'format': '{{{:d}, {:d}, {:d}, {:d}, {:d}, {:d}, {:d}, {:d}}}',
                 'gdb_expression': '$ymm14.v8_int32',
                },
        'ymm15': {'format': '{{{:d}, {:d}, {:d}, {:d}, {:d}, {:d}, {:d}, {:d}}}',
                 'gdb_expression': '$ymm15.v8_int32',
                },

    }

    sr_name = 'eflags'
    unemulated_instructions = []
    capstone_arch = CS_ARCH_X86
    capstone_mode = CS_MODE_32
    word_size = 32


class X86_64(X86):
    qemu_name = 'x86_64'
    gdb_name = 'i386:x86-64'
    registers = {'rax': 0,
                 'rbx': 1,
                 'rcx': 2,
                 'rdx': 3,
                 'rsi': 4,
                 'rdi': 5,
                 'rbp': 6,
                 'rsp': 7,
                 'r8': 8,
                 'r9': 9,
                 'r10': 10,
                 'r11': 11,
                 'r12': 12,
                 'r13': 13,
                 'r14': 14,
                 'r15': 15,
                 'rip': 16,
                 'pc': 16,
                 'eflags': 17,
                 'cs': 18,
                 'ss': 19,
                 'ds': 20,
                 'es': 21,
                 'fs': 22,
                 'gs': 23,
                 }
    capstone_mode = CS_MODE_64
    unemulated_instructions = []
    capstone_mode = CS_MODE_64
    word_size = 64
