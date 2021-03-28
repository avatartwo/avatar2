import os
from os.path import abspath
from time import sleep

from nose.tools import *

import socket

from avatar2 import *
from avatar2.peripherals.nucleo_usart import *

from pandare import ffi


PORT = 9997

panda = None
avatar = None
s = None
test_string = bytearray(b'Hello World !\n')

sram_dump = './tests/pyperipheral/sram_dump.bin'
rcc_dump  = './tests/pyperipheral/rcc_dump.bin'
firmware  = './tests/pyperipheral/firmware.bin'

with open(sram_dump, 'rb') as f:
    sram_data = f.read()

with open(rcc_dump, 'rb') as f:
    rcc_data = f.read()


@timed(7)
def setup_func():
    # There is only one pypanda instance in the process space allowed.
    # Unfortunately, we need a lot of hacks to make this working for CI tests.
    # So, beware the globals!
    global panda
    global avatar
    global s

    if panda is None:
        # Initiate the avatar-object
        avatar = Avatar(output_directory='/tmp/avatar', arch=ARM_CORTEX_M3)

        panda = avatar.add_target(PyPandaTarget, gdb_port=1236,
                                 entry_address=0x08005105)

        # Define the various memory ranges and store references to them
        avatar.add_memory_range(0x08000000, 0x1000000, file=firmware)
        avatar.add_memory_range(0x20000000, 0x14000)
        avatar.add_memory_range(0x40023000, 0x1000)

        avatar.init_targets()

        panda.pypanda.register_pyperipheral(NucleoUSART('USART', 0x40004400, 0x100,
                                                        nucleo_usart_port=PORT))

        time.sleep(.1)

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('127.0.0.1', PORT))

    panda.write_memory(0x20000000, len(sram_data), sram_data, raw=True)
    panda.write_memory(0x40023000, len(rcc_data), rcc_data, raw=True)

    panda.regs.pc = 0x08005105
    panda.regs.sp = 0x20014000

    panda.bp(0x0800419c) # Termination breakpoint to avoid qemu dying

@timed(8)
def teardown_func():
    #panda.shutdown()
    #avatar.shutdown()
    #time.sleep(1)
    pass



@with_setup(setup_func, teardown_func)
def test_nucleo_usart_read():
    panda.cont()

    data = s.recv(len(test_string), socket.MSG_WAITALL)
    assert_equal(data, test_string)


@with_setup(setup_func, teardown_func)
def test_panda_callback():
    recv_data = []
    def cb(env, pc, addr, size, buf):

        if addr == 0x40004404:
            recv_data.append(buf[0])


    cb_handle = panda.register_callback('mmio_before_write', cb)

    panda.cont()
    panda.wait()

    assert_equal(bytearray(recv_data), test_string)
    panda.disable_callback(cb_handle)


recv_data = []
@timed(11)
@with_setup(setup_func, teardown_func)
def test_panda_hook():
    def hook(env, tb, hook):
        global recv_data
        recv_data += [panda.pypanda.arch.get_reg(env, 'r0')]


    panda.add_hook(0x8004622, hook) # return address of serial_putc

    panda.cont()
    panda.wait()

    assert_equal(bytearray(recv_data), test_string)
    panda.pypanda.plugins['hooks'].disable_hooking()





@timed(10)
@with_setup(setup_func, teardown_func)
def test_nucleo_usart_debug_read():

    # pyperipherals in debug mode need to be read from/written to directly
    pyperiph = panda.pypanda.pyperipherals[0]


    s.send(b'Hello World')

    reply = bytearray()
    time.sleep(.1)

    while pyperiph.read_memory(0x40004400,4) & (1<<5) != 0:
        reply.append(pyperiph.read_memory(0x40004404,4))

    assert_equal(reply, b'Hello World')

    s.send(b'Hello World')
    reply = bytearray()
    time.sleep(.1)
    while pyperiph.read_memory(0x40004400,1) & (1<<5) != 0:
        reply.append(pyperiph.read_memory(0x40004404,1))

    assert_equal(reply, b'Hello World')


@timed(11)
@with_setup(setup_func, teardown_func)
def test_nucleo_usart_debug_write():
    pyperiph = panda.pypanda.pyperipherals[0]

    time.sleep(1)
    for c in test_string:
        pyperiph.write_memory(0x40004404, 1, c)
    reply =  s.recv(len(test_string), socket.MSG_WAITALL)
    assert_equal(reply, test_string)

    time.sleep(.1)
    for c in test_string:
        pyperiph.write_memory(0x40004404, 4, c)
    reply =  s.recv(len(test_string), socket.MSG_WAITALL)
    assert_equal(reply, test_string)






if __name__ == '__main__':
    #setup_func()
    #test_panda_callback()
    #teardown_func()
    #setup_func()
    #test_panda_hook()
    #teardown_func()
    pass

