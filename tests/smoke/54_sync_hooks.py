import avatar2
import os
import logging
import sys
import time
import threading
import subprocess

from nose.tools import *


# The TargetLauncher is ripped from the avatar1-example
# It is used to spawn and stop a qemu instance which is independent of avatar2.
class TargetLauncher(object):
    def __init__(self, cmd):
        self._cmd = cmd
        self._process = None
        self._thread = threading.Thread(target=self.run)
        self._thread.start()

    def stop(self):
        if self._process:
            print(self._process.kill())

    def run(self):
        print("TargetLauncher is starting process %s" %
              " ".join(['"%s"' % x for x in self._cmd]))
        self._process = subprocess.Popen(self._cmd)






def test_race():

    def hook_callback(avatar, *args, **kwargs):
        gdb = avatar.targets['gdbtest']
        pc = gdb.read_register("pc")
        assert pc is not None, f"ILLEGAL STATE {gdb.get_status()}"



    avatar = avatar2.Avatar(arch=avatar2.ARM)

    qemu = TargetLauncher([avatar.arch.get_qemu_executable(),
                           "-machine",  "virt",
                           "-gdb", "tcp::1234",
                           "-S",
                           "-nographic",
                           "-bios", "./tests/binaries/qemu_arm_test"])

    gdb = avatar.add_target(avatar2.GDBTarget,
                              name='gdbtest',
                              gdb_port=1234,
                              gdb_verbose_mi=False,
                              gdb_executable='/usr/bin/gdb-multiarch'
                            )

    # add breakpoint callback
    avatar.watchmen.add('BreakpointHit', when='after', callback=hook_callback, is_async=False)


    print("Init avatar targets...")
    avatar.init_targets()

    gdb.set_breakpoint(0x4)

    gdb.write_register('pc', 0)
    # Start running
    gdb.cont()

    # wait until we hit a breakpoint, once we hit the breakpoint, continue this python script
    print("waiting until we hit a breakpoint")
    gdb.wait()
    # add two breakpoints
    gdb.set_breakpoint(0x8)
    gdb.set_breakpoint(0xc)

    gdb.set_breakpoint(0x1000)

    # Continue executing from main
    gdb.cont()
    while True:
        # Wait until we hit a breakpoint
        gdb.wait()
        if gdb.regs.pc == 0x1000:
            break
        gdb.cont()


    qemu.stop()
    avatar.shutdown()

if __name__ == '__main__':
    test_race()
