import unittest

import tempfile
import os
import time
import intervaltree
import logging

from avatar2 import QemuTarget
from avatar2 import MemoryRange
from avatar2 import Avatar
from avatar2.archs import ARM, MIPS_24KF
from avatar2.targets import Target, TargetStates
from avatar2.message import *



TEST_DIR = '/tmp/testava'
ARCH = None
ARM_BASE_ADDR   = 0x08000000
MIPS_BASE_ADDR  = 0x1fc00000

ARM_BIN = (b'\x1e\x10\xa0\xe3'      # mov r1, #0x1e
           b'\x00\x00\x20\xe0'      # eor r0, r0, r0
           b'\x01\x00\x80\xe2'      # add r0, r0, #1
           b'\x01\x00\x50\xe1'      # cmp r0, r1
           b'\xfc\xff\xff\x1a'      # bne #8
           b'\x00\x00\x00\xe0'      # and r0, r0, r0
           b'\x00\x00\x00\xe0')     # and r0, r0, r0

MIPS_BIN = (b'\x24\x09\x00\x1e'     # addiu $t1, $zero, 0x1e
            b'\x01\x08\x40\x26'     # xor $t0, $t0, $t0
            b'\x21\x08\x00\x01'     # addi $t0, $t0, 1
            b'\x15\x09\xff\xfe'     # bne $t0, $t1, 8
            b'\x00\x00\x00\x00'     # nop 
            b'\x01\x08\x40\x24'     # and $t0, $t0, $t0
            b'\x01\x08\x40\x24')    # and $t0, $t0, $t0

X86_BIN = (b'\xbb\x1e\x00\x00\x00'  # mov ebx, 0x1e
           b'\x31\xc0'              # xor eax, eax
           b'\x83\xc0\x01'          # add eax, 1
           b'\x39\xd8'              # cmp eax, ebx
           b'\x75\xfc'              # jne 0xa
           b'\x21\xc0'              # and eax, eax
           b'\x21\xc0')             # and eax, eax

X86_64_BIN = (b'\x48\xc7\xc3\x1e\x00\x00\x00'   # mov rbx, 0x1e
              b'\x48\x31\xc0'                   # xor rax, rax
              b'\x48\x83\xc0\x01'               # add rax, 1
              b'\x48\x39\xd8'                   # cmp rax, rbx
              b'\x75\xfc'                       # jne 0xa
              b'\x48\x21\xc0'                   # and rax, rax
              b'\x48\x21\xc0')                  # and rax, rax

avatar = None
qemu = None
fake_target = None



class FakeTarget(object):
    name = 'fake'

    def __init__(self):
        pass


    def read_memory(*args, **kwargs):
        return 0xdeadbeef

    def write_memory(self, addr, size, val, *args, **kwargs):
        self.fake_write_addr = addr
        self.fake_write_size = size
        self.fake_write_val  = val
        return True



class QemuTargetTestCase(unittest.TestCase):


    def setUp(self):
        global avatar, qemu, fake_target

        self.rom_addr = None
        self.arch = None
        self.setup_arch()

        avatar = Avatar(arch=self.arch, output_directory=TEST_DIR)
        qemu = QemuTarget(avatar, name='qemu_test',
                          #firmware="./tests/binaries/qemu_arm_test",
                          firmware='%s/firmware' % TEST_DIR,
                         )
        fake_target = FakeTarget()

        dev1 = avatar.add_memory_range(0x101f2000, 0x1000, 'dev1', forwarded=True, 
                                       forwarded_to=fake_target,
                                       qemu_name='avatar-rmemory')

        mem1 = avatar.add_memory_range(self.rom_addr, 0x1000, 'mem1', 
                                       #file='%s/tests/binaries/qemu_arm_test' %
                                       #   os.getcwd())
                                       file='%s/firmware' % TEST_DIR)

    def setup_arch(self):

        ARCH = os.getenv('AVATAR2_ARCH')

        if ARCH == 'ARM':
            self.arch = ARM
            self.rom_addr = ARM_BASE_ADDR 
            firmware = ARM_BIN

        elif ARCH == 'MIPS':
            self.arch = MIPS_24KF
            self.rom_addr = MIPS_BASE_ADDR
            firmware = MIPS_BIN

        else:
            self.assertTrue(False, 'Invalid Achitecture')

        if not os.path.exists(TEST_DIR): os.makedirs(TEST_DIR)
        with open('%s/firmware' % TEST_DIR, 'wb') as f:
            f.write(firmware)

    def tearDown(self):
        qemu.shutdown()


    def test_initilization(self):
        qemu.init()
        qemu.wait()
        self.assertEqual(qemu.state, TargetStates.STOPPED, qemu.state)

    def test_step(self):
        qemu.init()
        qemu.wait()

        qemu.regs.pc=self.rom_addr
        qemu.step()

        pc = qemu.regs.pc
        self.assertEqual(pc, self.rom_addr + 4, pc)

    def test_memory_read(self):
        qemu.init()
        qemu.wait()

        mem = qemu.read_memory(self.rom_addr, 4)

        if ARCH == 'ARM':
            self.assertEqual(mem, 0xe3a0101e, mem)

        elif ARCH == 'MIPS':
            #self.assertEqual(mem, 0x2409001e, mem)
            self.assertEqual(mem, 0x1e000924, mem)

        else:
            self.assertTrue(False, "Architecture not supported")

    def test_memory_write(self):
        qemu.init()
        qemu.wait()

        qemu.write_memory(self.rom_addr, 4, 0x41414141)
        mem = qemu.read_memory(self.rom_addr, 4)
        self.assertEqual(mem, 0x41414141, mem)

    def test_remote_memory_write(self):
        qemu.init()
        qemu.wait()
        remote_memory_write = qemu.write_memory(0x101f2000,4,0x41414141)
        self.assertEqual(remote_memory_write, True)

        addr = fake_target.fake_write_addr
        size = fake_target.fake_write_size
        val  = fake_target.fake_write_val
        self.assertEqual(addr, 0x101f2000, addr)
        self.assertEqual(size, 4, size)
        self.assertEqual(val, 0x41414141, val)

    def test_remote_memory_read(self):
        qemu.init()
        qemu.wait()
        self.assertEqual(qemu.state, TargetStates.STOPPED, qemu.state)

        remote_memory_read = qemu.read_memory(0x101f2000,4)
        self.assertEqual(remote_memory_read, 0xdeadbeef, remote_memory_read)

