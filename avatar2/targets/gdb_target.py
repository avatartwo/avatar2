from avatar2.targets import Target, TargetStates
from avatar2.protocols.gdb import GDBProtocol

from .target import action_valid_decorator_factory, synchronize_state
from ..watchmen import watch

class GDBTarget(Target):
    def __init__(self, avatar,
                 gdb_executable=None, gdb_additional_args=None, 
                 gdb_ip='127.0.0.1', gdb_port=3333,
                 gdb_serial_device='/dev/ttyACM0',
                 gdb_serial_baud_rate=38400,
                 gdb_serial_parity='none',
                 gdb_verbose_mi=False,
                 serial=False,
                 enable_init_files=False,
                 local_binary=None,
                 arguments=None,
                 **kwargs
                 ):

        super(GDBTarget, self).__init__(avatar, **kwargs)

        self.gdb_executable = (gdb_executable if gdb_executable is not None
                               else self._arch.get_gdb_executable())
        self.gdb_additional_args = gdb_additional_args if gdb_additional_args else []
        self.gdb_ip = gdb_ip
        self.gdb_port = gdb_port
        self.gdb_serial_device = gdb_serial_device
        self.gdb_serial_baud_rate = gdb_serial_baud_rate
        self.gdb_serial_parity = gdb_serial_parity
        self._serial = serial
        self._local_binary = local_binary
        self._arguments = arguments
        self._enable_init_files = enable_init_files
        self._verbose_gdbmi = gdb_verbose_mi

    def init(self):

        gdb = GDBProtocol(gdb_executable=self.gdb_executable,
                          arch=self._arch,
                          additional_args=self.gdb_additional_args,
                          avatar=self.avatar, origin=self,
                          enable_init_files=self._enable_init_files,
                          binary=self._local_binary,
                          local_arguments=self._arguments,
                          verbose=self._verbose_gdbmi)

        # If we are debugging a program locally,
        # we do not need to establish any connections
        if not self._local_binary:
            if not self._serial:
                if gdb.remote_connect(ip=self.gdb_ip, port=self.gdb_port):
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
        else:
            self.update_state(TargetStates.INITIALIZED)

        self.protocols.set_all(gdb)

        if self._local_binary:
            self.wait(state=TargetStates.INITIALIZED)
        else:
            self.wait()

    @watch('TargetCont')
    @action_valid_decorator_factory(TargetStates.INITIALIZED, 'execution')
    @synchronize_state(TargetStates.RUNNING)
    def run(self, blocking=True):
        return self.protocols.execution.run()

    def cont(self, blocking=True):
        if self.state != TargetStates.INITIALIZED:
            super(GDBTarget, self).cont(blocking=blocking)
        else:
            self.run()

    @action_valid_decorator_factory(TargetStates.INITIALIZED, 'execution')
    def disable_aslr(self):
        self.protocols.execution.set_gdb_variable('disable-randomization',
                                                  'on')

    @action_valid_decorator_factory(TargetStates.INITIALIZED, 'execution')
    def enable_aslr(self):
        self.protocols.execution.set_gdb_variable('disable-randomization',
                                                  'off')
    
