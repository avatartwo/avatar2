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

def setup_func():
    global qemu
    global avatar

    firmware  = './tests/pyperipheral/firmware.bin'
    sram_dump = './tests/pyperipheral/sram_dump.bin'
    rcc_dump  = './tests/pyperipheral/rcc_dump.bin'


    # Initiate the avatar-object
    avatar = Avatar(output_directory='/tmp/avatar', arch=ARM_CORTEX_M3)

    qemu = avatar.add_target(QemuTarget, executable=QEMU_EXECUTABLE,
                             gdb_executable=GDB_EXECUTABLE, gdb_port=1236)
    qemu.log_items = 'in_asm'
    qemu.log_file = 'aaaa'

    # Define the various memory ranges and store references to them
    avatar.add_memory_range(0x08000000, 0x1000000, file=firmware)
    avatar.add_memory_range(0x20000000, 0x14000, file=sram_dump)
    avatar.add_memory_range(0x40004400, 0x100,
                                   emulate=NucleoUSART,
                                   nucleo_usart_port=PORT)
    avatar.add_memory_range(0x40023000, 0x1000, file=rcc_dump)


    avatar.init_targets()
    qemu.regs.sp = 0x20014000
    qemu.regs.pc = 0x08005104

    qemu.bp(0x0800419c) # Termination breakpoint to avoid qemu dying

def teardown_func():
    qemu.shutdown()
    avatar.shutdown()
    time.sleep(1)


@with_setup(setup_func, teardown_func)
def test_nucleo_usart_read():
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('127.0.0.1', PORT))
    qemu.cont()
    data = s.recv(13,socket.MSG_WAITALL)

    assert_equal(data, b'Hello World !')











if __name__ == '__main__':
    setup_func()
    test_nucleo_usart_read()
    teardown_func()

