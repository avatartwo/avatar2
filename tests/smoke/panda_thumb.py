import os
from os.path import abspath
from time import sleep

from nose.tools import *

import socket

from avatar2 import *
from avatar2.peripherals.nucleo_usart import *



'''
The ARM architecture encodes the thumbbit at a different bit in xpsr/cpsr based
on the used ISA version. The PandaTarget does not correctly emulate cortex-m
cpus yet, resulting into a thumbbit at the wrong location for this architecture.
The current version of QemuTarget, however, emulates correctly.
Hence, there is a divergence, which we fetch inside a watchmen in
avatar2/archs/arm.py
This test aims to validate that thiss approach works as intended.
'''


def setup_target(target_type):
    firmware  = './tests/pyperipheral/firmware.bin'
    sram_dump = './tests/pyperipheral/sram_dump.bin'
    rcc_dump  = './tests/pyperipheral/rcc_dump.bin'


    # Initiate the avatar-object
    avatar = Avatar(output_directory='/tmp/avatar', arch=ARM_CORTEX_M3)

    t = avatar.add_target(target_type, gdb_port=1236)

    # Define the various memory ranges and store references to them
    avatar.add_memory_range(0x08000000, 0x1000000, file=firmware)
    avatar.add_memory_range(0x20000000, 0x14000, file=sram_dump)
    avatar.add_memory_range(0x40004400, 0x100,
                                   emulate=NucleoUSART)
    avatar.add_memory_range(0x40023000, 0x1000, file=rcc_dump)

    avatar.init_targets()
    t.regs.sp = 0x20014000
    t.regs.pc = 0x08005105

    t.bp(0x0800419c) 

    return t


def test_panda_thumb():
    panda = setup_target(PandaTarget)
    panda.cont()
    time.sleep(1)
    assert_equal(panda.state, TargetStates.STOPPED)
    
    panda.avatar.shutdown()
    time.sleep(1)

def test_panda_not_working():
    panda = setup_target(QemuTarget)
    panda.cont()
    time.sleep(1)
    assert_equal(panda.state, TargetStates.EXITED)

    panda.avatar.shutdown()
    time.sleep(1)

if __name__ == '__main__':
    test_panda_thumb()

