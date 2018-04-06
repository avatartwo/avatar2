# this test demonstrates a race condition for target wait (used internally in
# cont()), present in avatar up to version 1.1.0.

import avatar2
import os
import logging

from time import sleep
from nose.tools import *


def test_wait_race():

    def delay(*args, **kwargs):
        sleep(1)

    binary_path = (os.path.dirname(os.path.abspath(__file__))
                   + '/../binaries/infinite_loop')

    #logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
    a = avatar2.Avatar(arch=avatar2.X86_64)
    gdb = a.add_target(avatar2.GDBTarget, local_binary=binary_path,
                       gdb_verbose_mi=False)
    a.watchmen.add('TargetWait', when='before', callback=delay)

    gdb.init()
    gdb.set_breakpoint('main')
    gdb.cont()
    gdb.wait()

    assert_equal(gdb.state, avatar2.TargetStates.STOPPED)

    # Stress test stepping
    for i in range(1000):
        gdb.step()

    a.shutdown()

if __name__ == '__main__':
    test_wait_race()
