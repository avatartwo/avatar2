from avatar2.protocols.gdb import GDBProtocol
import avatar2

import subprocess
import os
import time

from nose.tools import *

SLEEP_TIME = 1

MEM_ADDR = 0x555555554000
port = 4444
p = None
g = None

x86_regs = [u'rax', u'rbx', u'rcx', u'rdx', u'rsi', u'rdi', u'rbp', u'rsp',
            u'r8', u'r9', u'r10', u'r11', u'r12', u'r13', u'r14', u'r15',
            u'rip', u'eflags', u'cs', u'ss', u'ds', u'es', u'fs', u'gs']


def setup_helloworld():
    global p, g
    p = subprocess.Popen(
        'gdbserver --once 127.0.0.1:%d %s/tests/binaries/hello_world' %
        (port, os.getcwd()), shell=True)
    g = GDBProtocol(arch=avatar2.archs.X86_64)
    g.remote_connect(port=port)


def setup_inf_loop():
    global p, g
    p = subprocess.Popen(
        'gdbserver --once 127.0.0.1:%d %s/tests/binaries/infinite_loop' %
        (port, os.getcwd()), shell=True)
    g = GDBProtocol(arch=avatar2.archs.X86_64)
    g.remote_connect(port=port)


def teardown_func():
    g.shutdown()

@with_setup(setup_helloworld, teardown_func)
def test_register_names():
    regs = g.get_register_names()
    
    assert_list_equal(regs[:len(x86_regs)], x86_regs)


@with_setup(setup_helloworld, teardown_func)
def test_register_read_and_write():

    ret = g.write_register('rax', 1678)
    assert_equal(ret, True)
    ret = g.read_register('rax')
    assert_equal(ret, 1678)


@with_setup(setup_helloworld, teardown_func)
def test_break_run_and_read_write_mem():

    ret = g.set_breakpoint('main')
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


    ret = g.stop()
    assert_equal(ret, True)

    time.sleep(SLEEP_TIME)

    ret = g.step()
    assert_equal(ret, True)

    time.sleep(SLEEP_TIME)

@with_setup(setup_helloworld, teardown_func)
def test_watchpoint():
    ret = g.set_watchpoint(0x555555554754, read=True,
                           write=False)
    assert_equal(ret, True)

    ret = g.cont()
    assert_equal(ret, True)

    
    time.sleep(SLEEP_TIME)

    ret = g.read_memory(MEM_ADDR, 4)
    assert_equal(ret, 0x464c457f)

if __name__ == '__main__':
    setup_helloworld()
    test_break_run_and_read_write_mem() 
    teardown_func()
