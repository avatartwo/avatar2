import unittest

from avatar2.protocols.gdb import GDBProtocol
import avatar2

import subprocess
import os
import time

import sys

from os.path import dirname, abspath



SLEEP_TIME = 2

MEM_ADDR = 0x555555554000
MAIN_ADDR = 0x5555555546b4

XML_PATH = dirname(abspath((__file__))) \
         + '/../avatar2/plugins/gdb/x86_64-target.xml'

PORT = 4444
AV_GDB_PORT = 7777
X86_REGS = [u'rax', u'rbx', u'rcx', u'rdx', u'rsi', u'rdi', u'rbp', u'rsp',
            u'r8', u'r9', u'r10', u'r11', u'r12', u'r13', u'r14', u'r15',
            u'rip', u'eflags', u'cs', u'ss', u'ds', u'es', u'fs', u'gs']

avatar = None
gdb = None
process = None
sk = None


class GdbPluginTestCase(unittest.TestCase):

    def setUp(self):
        pass

    def setup_avatar_gdb_server(self):
        global avatar, sk

        avatar = avatar2.Avatar(arch=avatar2.archs.X86_64)
        gdb_target = avatar.add_target(avatar2.GDBTarget, gdb_port=AV_GDB_PORT)

        avatar.init_targets()
        avatar.load_plugin('gdbserver')
        sk = avatar.spawn_gdb_server(gdb_target, PORT, True, XML_PATH)

    def setup_env(self, binary):
        global process, gdb

        process = subprocess.Popen(['gdbserver', '--once', '127.0.0.1:%d' %
                                    AV_GDB_PORT, binary],
                                    stderr=subprocess.PIPE)
        
        out = str(process.stderr.readline())
        self.assertEqual(binary in out, True, out)
        out = str(process.stderr.readline())
        self.assertEqual(str(AV_GDB_PORT) in out, True, out)
        
        # create avatar instance offering the gdbserver
        self.setup_avatar_gdb_server()

        gdb = GDBProtocol(arch=avatar2.archs.X86_64)
        gdb.remote_connect(port=PORT)

    def tearDown(self):
        sk.shutdown()
        avatar.shutdown()
        gdb.shutdown()
        process.terminate()



class TestCaseOnHelloWorld(GdbPluginTestCase):

    def setUp(self):
        binary = '%s/tests/binaries/hello_world' % os.getcwd()
        self.setup_env(binary)


    def test_register_names(self):
        regs = gdb.get_register_names()
        
        self.assertListEqual(regs[:len(X86_REGS)], X86_REGS, regs)


    def test_register_read_and_write(self):

        ret = gdb.write_register('rbx', 1678)
        ret = gdb.read_register('rbx')
        self.assertEqual(ret, 1678, ret)


    def test_break_run_and_read_write_mem(self):

        ret = gdb.set_breakpoint(MAIN_ADDR) # we don't support execfile transfer yet
        self.assertEqual(ret, True, ret)

        ret = gdb.cont()
        self.assertEqual(ret, True, ret)
        # todo: enable waiting
        
        time.sleep(SLEEP_TIME)

        ret = gdb.read_memory(MEM_ADDR, 4)
        self.assertEqual(ret, 0x464c457f, ret)

        ret = gdb.write_memory(MEM_ADDR, 4, 0x41414141)
        self.assertEqual(ret, True, ret)

        ret = gdb.read_memory(MEM_ADDR, 4)
        self.assertEqual(ret, 0x41414141, ret)


class TestCaseOnInfiniteLoop(GdbPluginTestCase):

    def setUp(self):
        binary = '%s/tests/binaries/infinite_loop' % os.getcwd()
        self.setup_env(binary)


    def test_continue_stopping_stepping(self):

        ret = gdb.cont()
        self.assertEqual(ret, True, ret)

        time.sleep(SLEEP_TIME)

        ret = gdb.stop()
        self.assertEqual(ret, True, ret)

        time.sleep(SLEEP_TIME)

        ret = gdb.step()
        self.assertEqual(ret, True, ret)

