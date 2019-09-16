import os
from os.path import abspath
from time import sleep

from nose.tools import *

import socket

from avatar2 import *
from avatar2.peripherals.nucleo_usart import *



QEMU_EXECUTABLE = os.environ.get("QEMU_EXECUTABLE",
                    "targets/build/qemu/arm-softmmu/qemu-system-arm")
GDB_EXECUTABLE  = os.environ.get("GDB_EXECUTABLE", "gdb-multiarch")

PORT = 9997

qemu = None
avatar = None
test_string = bytearray(b'Hello World !\n')

@timed(7)
def setup_func():
    global qemu
    global avatar

    firmware  = './tests/pyperipheral/firmware.bin'
    sram_dump = './tests/pyperipheral/sram_dump.bin'
    rcc_dump  = './tests/pyperipheral/rcc_dump.bin'


    # Initiate the avatar-object
    avatar = Avatar(output_directory='/tmp/avatar', arch=ARM_CORTEX_M3)

    qemu = avatar.add_target(QemuTarget, executable=QEMU_EXECUTABLE,
                             gdb_executable=GDB_EXECUTABLE, gdb_port=1236,
                             entry_address=0x08005105)

    #qemu.log_items = ['in_asm']
    #qemu.log_file = 'bbb.txt'
    #qemu.entry_address=0x08005105
    # Define the various memory ranges and store references to them
    avatar.add_memory_range(0x08000000, 0x1000000, file=firmware)
    avatar.add_memory_range(0x20000000, 0x14000, file=sram_dump)
    avatar.add_memory_range(0x40004400, 0x100,
                                   emulate=NucleoUSART,
                                   nucleo_usart_port=PORT)
    avatar.add_memory_range(0x40023000, 0x1000, file=rcc_dump)

    avatar.init_targets()
    qemu.regs.sp = 0x20014000

    qemu.bp(0x0800419c) # Termination breakpoint to avoid qemu dying

@timed(8)
def teardown_func():
    qemu.shutdown()
    avatar.shutdown()
    time.sleep(1)


@with_setup(setup_func, teardown_func)
def test_nucleo_usart_read():
    
    #import IPython; IPython.embed()
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('127.0.0.1', PORT))
    qemu.cont()

    data = s.recv(len(test_string), socket.MSG_WAITALL)

    assert_equal(data, test_string)



@timed(10)
@with_setup(setup_func, teardown_func)
def test_nucleo_usart_debug_read():
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('127.0.0.1', PORT))
    s.send(b'Hello World')

    reply = bytearray()
    time.sleep(.1)
    while qemu.rm(0x40004400,4) & (1<<5) != 0:
        reply.append(qemu.rm(0x40004404,4))

    assert_equal(reply, b'Hello World')

    s.send(b'Hello World')
    reply = bytearray()
    time.sleep(.1)
    while qemu.rm(0x40004400,1) & (1<<5) != 0:
        reply.append(qemu.rm(0x40004404,1))

    assert_equal(reply, b'Hello World')
    
    

    
@timed(11)
@with_setup(setup_func, teardown_func)
def test_nucleo_usart_debug_write():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('127.0.0.1', PORT))


    time.sleep(.1)
    for c in test_string:
        qemu.wm(0x40004404, 1, c)
    reply =  s.recv(len(test_string), socket.MSG_WAITALL)
    assert_equal(reply, test_string)


    time.sleep(.1)
    for c in test_string:
        qemu.wm(0x40004404, 4, c)
    reply =  s.recv(len(test_string), socket.MSG_WAITALL)
    assert_equal(reply, test_string)

if __name__ == '__main__':
    setup_func()
    #test_nucleo_usart_debug_write()
    test_nucleo_usart_read()
    teardown_func()

