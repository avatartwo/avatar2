from avatar2 import QemuTarget
from avatar2 import MemoryRange
from avatar2.archs import ARM
from avatar2.targets import Target, TargetStates
from avatar2.message import *


import tempfile
import os
import time
import intervaltree
import logging

from nose.tools import *


QEMU_EXECUTABLE = os.environ.get("QEMU_EXECUTABLE",
                    "targets/build/qemu/arm-softmmu/qemu-system-arm")
GDB_EXECUTABLE  = os.environ.get("GDB_EXECUTABLE", "gdb-multiarch")

qemu = None
fake_avatar = None


class FakeQueue(object):
    def __init__(self):
        pass
    def put(self, message):
        if isinstance(message, UpdateStateMessage):
            message.origin.update_state(message.state)
        elif isinstance(message, RemoteMemoryReadMessage):
            range = avatar.memory_ranges[message.address].pop().data
            mem = range.forwarded_to.read_memory(message.address, message.size)
            message.origin.protocols.remote_memory.send_response(message.id, mem,
                                                                True)


class FakeWatchmen(object):
    def t(*args, **kwargs):
        pass

class FakeAvatar(object):

    def __init__(self):
        self.output_directory = tempfile.mkdtemp(suffix="_avatar")
        self.arch = ARM
        self.memory_ranges = intervaltree.IntervalTree()
        self.log = logging.getLogger()
        self.log.addHandler(logging.NullHandler())
        self.queue = FakeQueue()
        self.fast_queue = FakeQueue()
        self.watchmen = FakeWatchmen()

    def add_memory_range(self, address, size, name='', permissions='rwx', 
                         file=None, forwarded=False, forwarded_to=None, **kwargs
                        ):
        m = MemoryRange(address, size, name=name, permissions=permissions, 
                        file=file, forwarded=forwarded, 
                        forwarded_to=forwarded_to, **kwargs)
        self.memory_ranges[address:address+size] = m
        return m


class FakeTarget(object):
    def __init__(self):
        pass

    def read_memory(*args, **kwargs):
        return 0xdeadbeef

    def write_memory(addr, size, val):
        tar.fake_write_addr = addr
        tar.fake_write_size = size
        tar.fake_write_val  = val
        return True

def setup():
    global qemu
    global avatar
    avatar = FakeAvatar()
    qemu = QemuTarget(avatar, name='qemu_test',
                      firmware="./tests/binaries/qemu_arm_test",
                      gdb_executable=GDB_EXECUTABLE,
                      executable=QEMU_EXECUTABLE)
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
def test_remote_memory_read():
    global qemu
    global avatar

    qemu.init()
    qemu.wait()
    assert_equal(qemu.state, TargetStates.STOPPED)

    remote_memory_read = qemu.read_memory(0x101f2000,4)
    assert_equal(remote_memory_read, 0xdeadbeef)

    remote_memory_write = qemu.write_memory(270471168,4,0x41414141)
    assert_equal(remote_memory_write, True)


if __name__ == '__main__':
    setup()
    #test_remote_memory()
    test_initilization()
    teardown()
