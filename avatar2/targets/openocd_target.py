import sys

if sys.version_info < (3, 0):
    from Queue import PriorityQueue
else:
    from queue import PriorityQueue
import time
import os
from avatar2.targets import Target
from avatar2.protocols.openocd import OpenOCDProtocol
from avatar2.protocols.gdb import GDBProtocol
from avatar2.watchmen import watch


class OpenOCDTarget(Target):
    def __init__(self, avatar, executable=None,
                 openocd_script=None, additional_args=None,
                 tcl_port=6666,
                 gdb_executable=None, gdb_additional_args=None, gdb_port=3333,
                 **kwargs
                 ):

        if openocd_script and not os.path.exists(openocd_script):
            raise ValueError("OpenOCD script %s does not exist!" % openocd_script)
        super(OpenOCDTarget, self).__init__(avatar, **kwargs)

        self.executable = (executable if executable is not None
                           else self._arch.get_oocd_executable())
        self.avatar = avatar
        self.openocd_script = openocd_script
        self.additional_args = additional_args if additional_args else []

        self.gdb_executable = (gdb_executable if gdb_executable is not None
                               else self._arch.get_gdb_executable())
        self.tcl_port = tcl_port
        self.gdb_additional_args = gdb_additional_args if gdb_additional_args else []
        self.gdb_port = gdb_port

    @watch("TargetInit")
    def init(self):
        openocd = OpenOCDProtocol(self.avatar, self, self.openocd_script,
                                  openocd_executable=self.executable,
                                  additional_args=self.additional_args,
                                  tcl_port=self.tcl_port,
                                  gdb_port=self.gdb_port,
                                  output_directory=self.avatar.output_directory)
        time.sleep(.1)  # give openocd time to start. Find a better solution?
        self.log.debug("Connecting to OpenOCD telnet port")
        ocd_connected = openocd.connect()

        gdb = GDBProtocol(gdb_executable=self.gdb_executable,
                          arch=self._arch,
                          additional_args=self.gdb_additional_args,
                          avatar=self.avatar, origin=self)
        self.log.debug("Connecting to OpenOCD GDB port")
        gdb_connected = gdb.remote_connect(port=self.gdb_port)
        script_has_reset = False
        if self.openocd_script:
            with open(self.openocd_script) as f:
                script = f.read()
            if "reset halt" in script:
                self.log.debug("Not resetting target, script may have done it already")
                script_has_reset = True
        if ocd_connected:
            self.log.info("Successfully connected to OpenOCD target!")
        else:
            self.log.error("Failed to connect to OpenOCD target!")
        if ocd_connected and not script_has_reset:
            self.log.debug("Resetting target...")
            openocd.reset()

        self.protocols.set_all(gdb)
        self.protocols.monitor = openocd
        self.wait()
