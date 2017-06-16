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
    def __init__(self, avatar, executable="openocd",
                 openocd_script=None, additional_args=[],
                 telnet_port=4444,
                 gdb_executable='gdb', gdb_additional_args=[], gdb_port=3333,
                 **kwargs
                 ):

        super(OpenOCDTarget, self).__init__(avatar, **kwargs)

        self.executable = executable
        self.openocd_script = openocd_script
        self.additional_args = additional_args
        self.telnet_port = telnet_port
        self.gdb_executable = gdb_executable
        self.gdb_additional_args = gdb_additional_args
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
                          avatar_queue=self.avatar.queue, origin=self)

        time.sleep(.1)  # give openocd time to start. Find a better solution?

        if openocd.connect() and gdb.remote_connect(port=self.gdb_port):
            openocd.reset()
            self.log.info("Connected to Target")
        else:
            self.log.warning("Connecting failed")

        self._exec_protocol = gdb
        self._memory_protocol = gdb
        self._register_protocol = gdb
        self._signal_protocol = gdb
        self._monitor_protocol = openocd

        self.wait()
