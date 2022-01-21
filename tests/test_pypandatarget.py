import unittest

import socket
from os.path import abspath
from time import sleep

from avatar2 import *
from avatar2.peripherals.nucleo_usart import *



PORT = 9997
TEST_STRING = bytearray(b'Hello World !\n')

panda = None
avatar = None
sk = None

sram_dump = './tests/pyperipheral/sram_dump.bin'
rcc_dump  = './tests/pyperipheral/rcc_dump.bin'
firmware  = './tests/pyperipheral/firmware.bin'

with open(sram_dump, 'rb') as f:
    sram_data = f.read()

with open(rcc_dump, 'rb') as f:
    rcc_data = f.read()



class PypandaTargetTestCase(unittest.TestCase):

    #@timed(7)
    def setUp(self):
        # There is only one pypanda instance in the process space allowed.
        # Unfortunately, we need a lot of hacks to make this working for CI tests.
        # So, beware the globals!
        global panda, avatar, sk

        self.recv_data = []

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

            sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sk.connect(('127.0.0.1', PORT))

        panda.write_memory(0x20000000, len(sram_data), sram_data, raw=True)
        panda.write_memory(0x40023000, len(rcc_data), rcc_data, raw=True)

        panda.regs.pc = 0x08005105
        panda.regs.sp = 0x20014000

        panda.bp(0x0800419c) # Termination breakpoint to avoid qemu dying

    #@timed(8)
    def tearDown(self):
        #panda.shutdown()
        #avatar.shutdown()
        #time.sleep(1)
        pass


    def test_nucleo_usart_read(self):
        panda.cont()

        data = sk.recv(len(TEST_STRING), socket.MSG_WAITALL)
        self.assertEqual(data, TEST_STRING, data)


    def test_panda_callback(self):
        recv_data = []
        def cb(env, pc, addr, size, buf):

            if addr == 0x40004404:
                recv_data.append(buf[0])


        cb_handle = panda.register_callback('mmio_before_write', cb)

        panda.cont()
        panda.wait()

        self.assertEqual(bytearray(recv_data), TEST_STRING, bytearray(recv_data))
        panda.disable_callback(cb_handle)


    #@timed(11)
    def test_panda_hook(self):
        def hook(env, tb, hook):
            #global recv_data
            self.recv_data += [panda.pypanda.arch.get_reg(env, 'r0')]


        panda.add_hook(0x8004622, hook) # return address of serial_putc

        panda.cont()
        panda.wait()

        self.assertEqual(bytearray(self.recv_data), TEST_STRING, bytearray(self.recv_data))
        panda.pypanda.plugins['hooks'].disable_hooking()



    #@timed(10)
    def test_nucleo_usart_debug_read(self):

        # pyperipherals in debug mode need to be read from/written to directly
        pyperiph = panda.pypanda.pyperipherals[0]


        sk.send(b'Hello World')

        reply = bytearray()
        time.sleep(.1)

        while pyperiph.read_memory(0x40004400,4) & (1<<5) != 0:
            reply.append(pyperiph.read_memory(0x40004404,4))

        self.assertEqual(reply, b'Hello World', reply)

        sk.send(b'Hello World')
        reply = bytearray()
        time.sleep(.1)
        while pyperiph.read_memory(0x40004400,1) & (1<<5) != 0:
            reply.append(pyperiph.read_memory(0x40004404,1))

        self.assertEqual(reply, b'Hello World', reply)


    #@timed(11)
    def test_nucleo_usart_debug_write(self):
        pyperiph = panda.pypanda.pyperipherals[0]

        time.sleep(1)
        for c in TEST_STRING:
            pyperiph.write_memory(0x40004404, 1, c)
        reply =  sk.recv(len(TEST_STRING), socket.MSG_WAITALL)
        self.assertEqual(reply, TEST_STRING, reply)

        time.sleep(.1)
        for c in TEST_STRING:
            pyperiph.write_memory(0x40004404, 4, c)
        reply =  sk.recv(len(TEST_STRING), socket.MSG_WAITALL)
        self.assertEqual(reply, TEST_STRING, reply)

