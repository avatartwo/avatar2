from avatar2 import QemuTarget
from avatar2 import MemoryRange
from avatar2 import Avatar
from avatar2.archs import ARM, MIPS_24KF
from avatar2.targets import Target, TargetStates
from avatar2.message import *


import tempfile
import os
import time
import intervaltree
import logging

from nose.tools import *


qemu = None
fake_target = None
ARCH = None
rom_addr = None
test_dir = '/tmp/testava'


arm_bin = (b'\x1e\x10\xa0\xe3'      # mov r1, #0x1e
           b'\x00\x00\x20\xe0'      # eor r0, r0, r0
           b'\x01\x00\x80\xe2'      # add r0, r0, #1
           b'\x01\x00\x50\xe1'      # cmp r0, r1
           b'\xfc\xff\xff\x1a'      # bne #8
           b'\x00\x00\x00\xe0'      # and r0, r0, r0
           b'\x00\x00\x00\xe0')     # and r0, r0, r0

mips_bin = (b'\x24\x09\x00\x1e'     # addiu $t1, $zero, 0x1e
            b'\x01\x08\x40\x26'     # xor $t0, $t0, $t0
            b'\x21\x08\x00\x01'     # addi $t0, $t0, 1
            b'\x15\x09\xff\xfe'     # bne $t0, $t1, 8
            b'\x00\x00\x00\x00'     # nop 
            b'\x01\x08\x40\x24'     # and $t0, $t0, $t0
            b'\x01\x08\x40\x24')    # and $t0, $t0, $t0

x86_bin = (b'\xbb\x1e\x00\x00\x00'  # mov ebx, 0x1e
           b'\x31\xc0'              # xor eax, eax
           b'\x83\xc0\x01'          # add eax, 1
           b'\x39\xd8'              # cmp eax, ebx
           b'\x75\xfc'              # jne 0xa
           b'\x21\xc0'              # and eax, eax
           b'\x21\xc0')             # and eax, eax

x86_64_bin = (b'\x48\xc7\xc3\x1e\x00\x00\x00'   # mov rbx, 0x1e
              b'\x48\x31\xc0'                   # xor rax, rax
              b'\x48\x83\xc0\x01'               # add rax, 1
              b'\x48\x39\xd8'                   # cmp rax, rbx
              b'\x75\xfc'                       # jne 0xa
              b'\x48\x21\xc0'                   # and rax, rax
              b'\x48\x21\xc0')                  # and rax, rax



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


def setup(gdb_unix_socket_path=None):
    global qemu
    global avatar
    global fake_target

    arch = setup_ARCH()

    avatar = Avatar(arch=arch, output_directory=test_dir, configure_logging=False)
    qemu = QemuTarget(avatar, name='qemu_test',
                      #firmware="./tests/binaries/qemu_arm_test",
                      firmware='%s/firmware' % test_dir,
                      gdb_unix_socket_path=gdb_unix_socket_path,
                      )
    fake_target = FakeTarget()

    dev1 = avatar.add_memory_range(0x101f2000, 0x1000, 'dev1', forwarded=True, 
                                   forwarded_to=fake_target,
                                   qemu_name='avatar-rmemory')

    mem1 = avatar.add_memory_range(rom_addr, 0x1000, 'mem1', 
                                #file='%s/tests/binaries/qemu_arm_test' %
                                #   os.getcwd())
                                file='%s/firmware' % test_dir)

def setup_ARCH():
    global ARCH
    global rom_addr

    ARCH = os.getenv('AVATAR2_ARCH')

    if ARCH == 'ARM':
        arch = ARM
        firmware = arm_bin
        rom_addr = 0x08000000

    elif ARCH == 'MIPS':
        arch = MIPS_24KF
        firmware = mips_bin
        rom_addr = 0x1fc00000

    else:
        assert False, 'Invalid Achitecture'

    if not os.path.exists(test_dir): os.makedirs(test_dir)
    with open('%s/firmware' % test_dir, 'wb') as f:
        f.write(firmware)

    return arch

def teardown():
    global qemu
    qemu.shutdown()


@with_setup(setup, teardown)
def test_initialization():
    global qemu

    qemu.init()
    qemu.wait()
    assert_equal(qemu.state, TargetStates.STOPPED)

@with_setup(lambda: setup(gdb_unix_socket_path="/tmp/test_sock"), teardown)
def test_initialization_unix():
    global qemu

    qemu.init()
    qemu.wait()

    assert_equal(qemu.state, TargetStates.STOPPED)
    qemu.shutdown()

@with_setup(setup, teardown)
def test_step():
    global qemu
    global ARCH

    qemu.init()
    qemu.wait()

    qemu.regs.pc=rom_addr
    qemu.step()
    assert_equal(qemu.regs.pc, rom_addr + 4)


@with_setup(setup, teardown)
def test_memory_read():
    global qemu
    global ARCH

    qemu.init()
    qemu.wait()

    mem = qemu.read_memory(rom_addr,4)

    if ARCH == 'ARM':
        assert_equal(mem, 0xe3a0101e)

    elif ARCH == 'MIPS':
        #assert_equal(mem, 0x2409001e)
        assert_equal(mem, 0x1e000924)

    else:
        assert False, "Architecture not supported"


@with_setup(setup, teardown)
def test_memory_write():
    global qemu

    qemu.init()
    qemu.wait()

    qemu.write_memory(rom_addr,4, 0x41414141)
    mem = qemu.read_memory(rom_addr,4)
    assert_equal(mem, 0x41414141)


@with_setup(setup, teardown)
def test_remote_memory_write():
    global qemu
    global avatar

    qemu.init()
    qemu.wait()
    remote_memory_write = qemu.write_memory(0x101f2000,4,0x41414141)
    assert_equal(remote_memory_write, True)

    assert_equal(fake_target.fake_write_addr, 0x101f2000)
    assert_equal(fake_target.fake_write_size, 4)
    assert_equal(fake_target.fake_write_val, 0x41414141)


@with_setup(setup, teardown)
def test_remote_memory_read():
    global qemu
    global avatar

    qemu.init()
    qemu.wait()
    assert_equal(qemu.state, TargetStates.STOPPED)

    remote_memory_read = qemu.read_memory(0x101f2000,4)
    assert_equal(remote_memory_read, 0xdeadbeef)


if __name__ == '__main__':
    setup()
    #test_remote_memory()
    test_initilization()
    teardown()
