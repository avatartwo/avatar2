# this test demonstrates a race condition for target wait (used internally in
# cont()), present in avatar up to version 1.1.0.

import avatar2
import os
from nose.tools import *
from time import sleep

def test_wait_race():

    def delay(*args, **kwargs):
        sleep(1)


    binary_path = (os.path.dirname(os.path.abspath(__file__))
                   + '/../binaries/hello_world')

    a = avatar2.Avatar(arch=avatar2.X86_64)
    gdb = a.add_target(avatar2.GDBTarget, local_binary=binary_path,
                       gdb_verbose_mi=True)
    a.watchmen.add('TargetWait', when='before', callback=delay)
    gdb.init()
    gdb.set_breakpoint('main')
    gdb.cont()


if __name__ == '__main__':
    test_wait_race()
