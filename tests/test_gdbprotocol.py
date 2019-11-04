from avatar2.protocols.gdb import GDBProtocol
import avatar2

import subprocess
import os
import time

from nose.tools import *

SLEEP_TIME = 1

port = 4444
p = None
g = None

x86_regs = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi',
            'edi', 'eip', 'eflags', 'cs', 'ss', 'ds', 'es', 'fs', 'gs']


def setup_helloworld():
    global p, g
    p = subprocess.Popen(
        'gdbserver --once 127.0.0.1:%d %s/tests/binaries/hello_world' % 
        (port, os.getcwd()), shell=True)
    g = GDBProtocol(arch=avatar2.archs.X86)
    g.remote_connect(port=port)


def setup_inf_loop():
    global p, g
    p = subprocess.Popen(
        'gdbserver --once 127.0.0.1:%d %s/tests/binaries/infinite_loop' %
        (port, os.getcwd()), shell=True)
    g = GDBProtocol(arch=avatar2.archs.X86)
    g.remote_connect(port=port)


def teardown_func():
    g.shutdown()

@with_setup(setup_helloworld, teardown_func)
def test_register_names():
    regs = g.get_register_names()
    assert_list_equal(regs[:16], x86_regs)


@with_setup(setup_helloworld, teardown_func)
def test_register_read_and_write():

    ret = g.write_register('eax', 1678)
    assert_equal(ret, True)
    ret = g.read_register('eax')
    assert_equal(ret, 1678)


@with_setup(setup_helloworld, teardown_func)
def test_break_run_and_read_write_mem():
    ret = g.set_breakpoint('main')
    assert_equal(ret, True)

    ret = g.cont()
    assert_equal(ret, True)
    # todo: enable waiting
    
    time.sleep(SLEEP_TIME)

    ret = g.read_memory(0x08048000, 4)
    assert_equal(ret, 0x464c457f)

    ret = g.write_memory(0x08048000, 4, 0x41414141)
    assert_equal(ret, True)

    ret = g.read_memory(0x08048000, 4)
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
    ret = g.set_watchpoint(0x080484c0, read=True,
                           write=False)
    assert_equal(ret, True)

    ret = g.cont()
    assert_equal(ret, True)

    
    time.sleep(SLEEP_TIME)

    ret = g.read_memory(0x08048000, 4)
    assert_equal(ret, 0x464c457f)

if __name__ == '__main__':
    setup_helloworld()
    test_break_run_and_read_write_mem()
    teardown_func()
