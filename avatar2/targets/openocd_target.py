import sys

if sys.version_info < (3, 0):
    from Queue import PriorityQueue
else:
    from queue import PriorityQueue
import time

from avatar2.targets import Target
from avatar2.protocols.gdb import GDBProtocol
from avatar2.protocols.openocd import OpenOCDProtocol


class OpenOCDTarget(Target):
    def __init__(self, avatar, executable=None,
                 openocd_script=None, additional_args=None,
                 telnet_port=4444,
                 gdb_executable=None, gdb_additional_args=None, gdb_port=3333,
                 **kwargs
                 ):

        super(OpenOCDTarget, self).__init__(avatar, **kwargs)

        self.executable = (executable if executable is not None
                           else self._arch.get_oocd_executable())
        self.openocd_script = openocd_script
        self.additional_args = additional_args if additional_args else []
        self.telnet_port = telnet_port

        self.gdb_executable = (gdb_executable if gdb_executable is not None
                               else self._arch.get_gdb_executable())
        self.gdb_additional_args = gdb_additional_args if gdb_additional_args else []
        self.gdb_port = gdb_port

    def init(self):
        openocd = OpenOCDProtocol(self.openocd_script,
                                  openocd_executable=self.executable,
                                  additional_args=self.additional_args,
                                  telnet_port=self.telnet_port,
                                  gdb_port=self.gdb_port,
                                  origin=self,
                                  output_directory=self.avatar.output_directory)

        gdb = GDBProtocol(gdb_executable=self.gdb_executable,
                          arch=self._arch,
                          additional_args=self.gdb_additional_args,
                          avatar=self.avatar, origin=self)

        time.sleep(.1)  # give openocd time to start. Find a better solution?

        if openocd.connect() and gdb.remote_connect(port=self.gdb_port):
            openocd.reset()
            self.log.info("Connected to Target")
        else:
            self.log.warning("Connecting failed")

        self.protocols.set_all(gdb)
        self.protocols.monitor = openocd

        self.wait()
