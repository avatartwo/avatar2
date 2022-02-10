import unittest

import socket
from os.path import dirname, realpath
from time import sleep

from avatar2 import *
from avatar2.peripherals.nucleo_usart import *



PORT = 9997
TEST_STRING = bytearray(b'Hello World !\n')

dir_path = dirname(realpath(__file__))
sram_dump = '%s/pyperipheral/sram_dump.bin' % dir_path
rcc_dump  = '%s/pyperipheral/rcc_dump.bin' % dir_path
firmware  = '%s/pyperipheral/firmware.bin' % dir_path

with open(sram_dump, 'rb') as f:
    sram_data = f.read()

with open(rcc_dump, 'rb') as f:
    rcc_data = f.read()



class PypandaTargetTestCase(unittest.TestCase):

    panda = None
    avatar = None
    sk = None

    @classmethod
    def setUpClass(cls):

        # Initiate the avatar-object
        cls.avatar = Avatar(output_directory='/tmp/avatar', arch=ARM_CORTEX_M3)

        cls.panda = cls.avatar.add_target(PyPandaTarget, gdb_port=1236,
                                            entry_address=0x08005105)

        # Define the various memory ranges and store references to them
        cls.avatar.add_memory_range(0x08000000, 0x1000000, file=firmware)
        cls.avatar.add_memory_range(0x20000000, 0x14000)
        cls.avatar.add_memory_range(0x40023000, 0x1000)

        cls.avatar.init_targets()

        cls.panda.pypanda.register_pyperipheral(NucleoUSART('USART', 0x40004400, 0x100,
                                                             nucleo_usart_port=PORT))

        time.sleep(1)

        cls.sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        cls.sk.connect(('127.0.0.1', PORT))

    @classmethod
    def tearDownClass(cls):
        cls.panda.shutdown()
        cls.avatar.shutdown()
        cls.sk.close()
        time.sleep(10)


    #@timed(7)
    def setUp(self):

        self.recv_data = []

        self.panda.write_memory(0x20000000, len(sram_data), sram_data, raw=True)
        self.panda.write_memory(0x40023000, len(rcc_data), rcc_data, raw=True)

        self.panda.regs.pc = 0x08005105
        self.panda.regs.sp = 0x20014000

        self.panda.bp(0x0800419c) # Termination breakpoint to avoid qemu dying

    #@timed(8)
    def tearDown(self):
        pass


    def test_nucleo_usart_read(self):
        self.panda.cont()

        data = self.sk.recv(len(TEST_STRING), socket.MSG_WAITALL)
        self.assertEqual(data, TEST_STRING, data)

        self.panda.wait()


    def test_panda_callback(self):
        recv_data = []
        def cb(env, pc, addr, size, buf):

            if addr == 0x40004404:
                recv_data.append(buf[0])


        cb_handle = self.panda.register_callback('mmio_before_write', cb)

        self.panda.cont()
        self.panda.wait()

        self.assertEqual(bytearray(recv_data), TEST_STRING, bytearray(recv_data))
        self.panda.disable_callback(cb_handle)


    #@timed(11)
    def test_panda_hook(self):
        def hook(env, tb, hook):
            #global recv_data
            self.recv_data += [self.panda.pypanda.arch.get_reg(env, 'r0')]


        self.panda.add_hook(0x8004622, hook) # return address of serial_putc

        self.panda.cont()
        self.panda.wait()

        self.assertEqual(bytearray(self.recv_data), TEST_STRING, bytearray(self.recv_data))
        self.panda.pypanda.plugins['hooks'].disable_hooking()



    #@timed(10)
    def test_nucleo_usart_debug_read(self):

        # pyperipherals in debug mode need to be read from/written to directly
        pyperiph = self.panda.pypanda.pyperipherals[0]


        self.sk.send(b'Hello World')

        reply = bytearray()
        time.sleep(.1)

        while pyperiph.read_memory(0x40004400,4) & (1<<5) != 0:
            reply.append(pyperiph.read_memory(0x40004404,4))

        self.assertEqual(reply, b'Hello World', reply)

        self.sk.send(b'Hello World')
        reply = bytearray()
        time.sleep(.1)
        while pyperiph.read_memory(0x40004400,1) & (1<<5) != 0:
            reply.append(pyperiph.read_memory(0x40004404,1))

        self.assertEqual(reply, b'Hello World', reply)


    #@timed(11)
    def test_nucleo_usart_debug_write(self):
        pyperiph = self.panda.pypanda.pyperipherals[0]

        time.sleep(1)
        for c in TEST_STRING:
            pyperiph.write_memory(0x40004404, 1, c)
        reply =  self.sk.recv(len(TEST_STRING), socket.MSG_WAITALL)
        self.assertEqual(reply, TEST_STRING, reply)

        time.sleep(.1)
        for c in TEST_STRING:
            pyperiph.write_memory(0x40004404, 4, c)
        reply =  self.sk.recv(len(TEST_STRING), socket.MSG_WAITALL)
        self.assertEqual(reply, TEST_STRING, reply)



if __name__ == '__main__':
    unittest.main()
