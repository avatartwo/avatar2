from avatar2 import QemuTarget
from avatar2 import MemoryRange
from avatar2 import Avatar
from avatar2.archs import ARM
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

def setup():
    global qemu
    global avatar
    global fake_target
    avatar = Avatar(output_directory='/tmp/testava')
    qemu = QemuTarget(avatar, name='qemu_test',
                      firmware="./tests/binaries/qemu_arm_test",
                      )
    fake_target = FakeTarget()

    dev1 = avatar.add_memory_range(0x101f2000, 0x1000, 'dev1', forwarded=True, 
                                   forwarded_to=fake_target,
                                   qemu_name='avatar-rmemory')

    mem1 = avatar.add_memory_range(0x8000000, 0x1000, 'mem1', 
                                file='%s/tests/binaries/qemu_arm_test' % 
                                   os.getcwd())

def teardown():
    global qemu
    qemu.shutdown()


@with_setup(setup, teardown)
def test_initilization():
    global qemu

    qemu.init()
    qemu.wait()
    assert_equal(qemu.state, TargetStates.STOPPED)


@with_setup(setup, teardown)
def test_step():
    global qemu

    qemu.init()
    qemu.wait()
    qemu.regs.pc=0x08000000
    qemu.step()
    assert_equal(qemu.regs.pc, 0x08000004)


@with_setup(setup, teardown)
def test_memory_read():
    global qemu

    qemu.init()
    qemu.wait()

    mem = qemu.read_memory(0x08000000,4)
    assert_equal(mem, 0xe3a0101e)


@with_setup(setup, teardown)
def test_memory_write():
    global qemu

    qemu.init()
    qemu.wait()
    qemu.write_memory(0x08000000,4, 0x41414141)
    mem = qemu.read_memory(0x08000000,4)
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
