from capstone import *

from .architecture import Architecture


class X86(Architecture):
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
                 'eflags': 9,
                 'cs': 10,
                 'ss': 11,
                 'ds': 12,
                 'es': 13,
                 'fs': 14,
                 'gs': 15, }
    unemulated_instructions = []
    capstone_arch = CS_ARCH_X86
    capstone_mode = CS_MODE_32


class X86_64(Architecture):
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
                 'r8 ': 8,
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
    unemulated_instructions = []
