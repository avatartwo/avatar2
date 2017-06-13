from avatar2.targets import Target
from avatar2.protocols.gdb import GDBProtocol


class GDBTarget(Target):

    def __init__(self, name, avatar, 
                 gdb_executable='gdb', gdb_additional_args=[], gdb_port=3333,
                 gdb_serial_device='/dev/ttyACM0',
                 gdb_serial_baud_rate=38400,
                 gdb_serial_parity='none',
                 serial=False
                ):

        super(GDBTarget, self).__init__(name, avatar)

        self.gdb_executable = gdb_executable
        self.gdb_additional_args = gdb_additional_args
        self.gdb_port = gdb_port
        self.gdb_serial_device = gdb_serial_device
        self.gdb_serial_baud_rate = gdb_serial_baud_rate
        self.gdb_serial_parity = gdb_serial_parity
        self._serial = serial

    def init(self):

        gdb = GDBProtocol(gdb_executable=self.gdb_executable,
                          arch=self._arch,
                          additional_args=self.gdb_additional_args,
                          avatar_queue=self.avatar.queue, origin=self)

        if not self._serial:
            if gdb.remote_connect(port=self.gdb_port):
                self.log.info("Connected to Target")
            else:
                self.log.warning("Connecting failed")
        else:
            if gdb.remote_connect_serial(device=self.gdb_serial_device,
                                     baud_rate=self.gdb_serial_baud_rate,
                                     parity=self.gdb_serial_parity):
                self.log.info("Connected to Target")
            else:
                self.log.warning("Connecting failed")


        self._exec_protocol = gdb
        self._memory_protocol = gdb
        self._register_protocol = gdb
        self._signal_protocol = gdb
        self._monitor_protocol = None

        self.wait()
