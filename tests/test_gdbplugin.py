from avatar2.protocols.gdb import GDBProtocol
import avatar2

import subprocess
import os
import time

import sys

from os.path import dirname, abspath

from nose.tools import *

SLEEP_TIME = 2

MEM_ADDR = 0x555555554000
MAIN_ADDR = 0x5555555546b4

XML_PATH = dirname(abspath((__file__))) \
         + '/../avatar2/plugins/gdb/x86_64-target.xml'

port = 4444
avatar_gdb_port = 7777
a = None
s = None
p = None
g = None

x86_regs = [u'rax', u'rbx', u'rcx', u'rdx', u'rsi', u'rdi', u'rbp', u'rsp',
            u'r8', u'r9', u'r10', u'r11', u'r12', u'r13', u'r14', u'r15',
            u'rip', u'eflags', u'cs', u'ss', u'ds', u'es', u'fs', u'gs']

def setup_avatar_gdb_server():
    global a,s
    a = avatar2.Avatar(arch=avatar2.archs.X86_64)
    gdb_target = a.add_target(avatar2.GDBTarget, gdb_port=avatar_gdb_port)

    a.init_targets()
    a.load_plugin('gdbserver')
    s = a.spawn_gdb_server(gdb_target, port, True, XML_PATH)



def setup_helloworld():
    global p, g, port


    binary = '%s/tests/binaries/hello_world' % os.getcwd()
    p = subprocess.Popen(['gdbserver', '--once', '127.0.0.1:%d' %
                          avatar_gdb_port, binary],
                        stderr=subprocess.PIPE)
    
    out = str(p.stderr.readline())
    assert_equal(binary in out, True)
    out = str(p.stderr.readline())
    assert_equal(str(avatar_gdb_port) in out, True)
    
    # create avatar instance offering the gdbserver
    setup_avatar_gdb_server()

    g = GDBProtocol(arch=avatar2.archs.X86_64)
    g.remote_connect(port=port)


def setup_inf_loop():
    global p, g, port

    binary = '%s/tests/binaries/infinite_loop' % os.getcwd()
    p = subprocess.Popen(['gdbserver', '--once', '127.0.0.1:%d' %
                          avatar_gdb_port, binary],
                        stderr=subprocess.PIPE)

    out = str(p.stderr.readline())
    assert_equal(binary in out, True)
    out = str(p.stderr.readline())
    assert_equal(str(avatar_gdb_port) in out, True)

    setup_avatar_gdb_server()
    g = GDBProtocol(arch=avatar2.archs.X86_64)
    g.remote_connect(port=port)


def teardown_func():
    s.shutdown()
    a.shutdown()
    g.shutdown()
    p.terminate()

@with_setup(setup_helloworld, teardown_func)
def test_register_names():
    regs = g.get_register_names()
    
    assert_list_equal(regs[:len(x86_regs)], x86_regs)


@with_setup(setup_helloworld, teardown_func)
def test_register_read_and_write():

    ret = g.write_register('rbx', 1678)
    ret = g.read_register('rbx')
    assert_equal(ret, 1678)


@with_setup(setup_helloworld, teardown_func)
def test_break_run_and_read_write_mem():

    ret = g.set_breakpoint(MAIN_ADDR) # we don't support execfile transfer yet
    assert_equal(ret, True)

    ret = g.cont()
    assert_equal(ret, True)
    # todo: enable waiting
    
    time.sleep(SLEEP_TIME)

    ret = g.read_memory(MEM_ADDR, 4)
    assert_equal(ret, 0x464c457f)

    ret = g.write_memory(MEM_ADDR, 4, 0x41414141)
    assert_equal(ret, True)

    ret = g.read_memory(MEM_ADDR, 4)
    assert_equal(ret, 0x41414141)

@with_setup(setup_inf_loop, teardown_func)
def test_continue_stopping_stepping():

    ret = g.cont()
    assert_equal(ret, True)

    time.sleep(SLEEP_TIME)

    ret = g.stop()
    assert_equal(ret, True)

    time.sleep(SLEEP_TIME)

    ret = g.step()
    assert_equal(ret, True)

if __name__ == '__main__':
    setup_inf_loop()
    test_continue_stopping_stepping()
    teardown_func()
