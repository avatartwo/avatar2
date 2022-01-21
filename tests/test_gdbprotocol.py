import unittest

from avatar2.protocols.gdb import GDBProtocol
import avatar2

import subprocess
import os
import time
import re



SLEEP_TIME = 1

MEM_ADDR = 0x555555400000
PORT = 4444

X86_REGS = [u'rax', u'rbx', u'rcx', u'rdx', u'rsi', u'rdi', u'rbp', u'rsp',
            u'r8', u'r9', u'r10', u'r11', u'r12', u'r13', u'r14', u'r15',
            u'rip', u'eflags', u'cs', u'ss', u'ds', u'es', u'fs', u'gs']

process = None
gdb = None


class GdbProtocolTestCase(unittest.TestCase):

    def setUp(self):
        pass 

    def setup_env(self, binary):
        global process, gdb

        process = subprocess.Popen(['gdbserver', '--once', '127.0.0.1:%d' % PORT, binary],
                                    stderr=subprocess.PIPE)
        
        out = str(process.stderr.readline())
        self.assertEqual(binary in out, True, out)
        out = str(process.stderr.readline())
        self.assertEqual(str(PORT) in out, True, out)
        
        gdb = GDBProtocol(arch=avatar2.archs.X86_64)
        gdb.remote_connect(port=PORT)

        # let's resolve the base address of the binary
        ret, out = gdb.console_command("p &main")
        main_addr = int(re.search("0x[0-9a-f]+", out).group(0), 16)
        self.base_address = main_addr - main_addr % 0x1000


    def tearDown(self):
        gdb.shutdown()
        process.terminate()


class GDBProtocolTestCaseOnHelloWorld(GdbProtocolTestCase):

    def setUp(self):
        binary = '%s/tests/binaries/hello_world' % os.getcwd()
        self.setup_env(binary)


    def test_register_names(self):
        regs = gdb.get_register_names()
        
        self.assertListEqual(regs[:len(X86_REGS)], X86_REGS)

    def test_register_read_and_write(self):

        ret = gdb.write_register('rax', 1678)
        self.assertEqual(ret, True, ret)
        ret = gdb.read_register('rax')
        self.assertEqual(ret, 1678, ret)

    def test_break_run_and_read_write_mem(self):

        ret = gdb.set_breakpoint('main')
        self.assertEqual(ret, True, ret)

        ret = gdb.cont()
        self.assertEqual(ret, True, ret)
        # todo: enable waiting
        
        time.sleep(SLEEP_TIME)

        ret = gdb.read_memory(self.base_address, 4)
        self.assertEqual(ret, 0x464c457f, ret)

        ret = gdb.write_memory(self.base_address, 4, 0x41414141)
        self.assertEqual(ret, True, ret)

        ret = gdb.read_memory(self.base_address, 4)
        self.assertEqual(ret, 0x41414141, ret)

    def test_watchpoint(self):
        ret = gdb.set_watchpoint(self.base_address+0x754, read=True,
                                    write=False)
        self.assertEqual(ret, True, ret)

        ret = gdb.cont()
        self.assertEqual(ret, True, ret)

        
        time.sleep(SLEEP_TIME)

        ret = gdb.read_memory(MEM_ADDR, 4)
        self.assertEqual(ret, 0x464c457f, ret)


class GDBProtocolTestCaseOnInfiniteLoop(GdbProtocolTestCase):


    def setUp(self):
        binary = '%s/tests/binaries/infinite_loop' % os.getcwd()
        self.setup_env(binary)


    def test_continue_stopping_stepping(self):

        ret = gdb.cont()
        self.assertEqual(ret, True, ret)


        ret = gdb.stop()
        self.assertEqual(ret, True, ret)

        time.sleep(SLEEP_TIME)

        ret = gdb.step()
        self.assertEqual(ret, True, ret)

        time.sleep(SLEEP_TIME)


