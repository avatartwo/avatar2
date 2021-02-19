import json
from subprocess import Popen
from os.path import isfile, exists

from avatar2.protocols.gdb import GDBProtocol
from avatar2.protocols.qmp import QMPProtocol
from avatar2.protocols.remote_memory import RemoteMemoryProtocol
from avatar2.targets import Target

from avatar2.installer.config import QEMU, GDB_MULTI
from avatar2.watchmen import watch


class QemuTarget(Target):
    """
    """


    def __init__(self, avatar,
                 executable=None,
                 cpu_model=None, firmware=None,
                 gdb_executable=None, gdb_port=3333,
                 additional_args=None, gdb_additional_args=None,
                 gdb_verbose=False,
                 qmp_port=3334,
                 entry_address=0x00,
                 log_items=None,
                 log_file=None,
                 system_clock_scale=None,
                 **kwargs):
        super(QemuTarget, self).__init__(avatar, **kwargs)

        # Qemu parameters
        self.system_clock_scale = system_clock_scale
        if hasattr(self, 'executable') is False and self.__class__ == QemuTarget:
            self.executable = (executable if executable is not None
                               else self._arch.get_qemu_executable())
        self.fw = firmware
        self.cpu_model = cpu_model
        self.entry_address = entry_address
        self.additional_args = additional_args if additional_args else []

        # gdb parameters
        self.gdb_executable = (gdb_executable if gdb_executable is not None
                               else self._arch.get_gdb_executable())


        self.gdb_port = gdb_port
        self.gdb_additional_args = gdb_additional_args if gdb_additional_args else []
        self.gdb_verbose = gdb_verbose

        self.qmp_port = qmp_port

        self._process = None
        self._entry_address = entry_address
        self._memory_mapping = avatar.memory_ranges

        self._rmem_rx_queue_name = '/{:s}_rx_queue'.format(self.name)
        self._rmem_tx_queue_name = '/{:s}_tx_queue'.format(self.name)

        self.log_items = log_items
        self.log_file  = log_file

        self.qemu_config_file =  ("%s/%s_conf.json" %
            (self.avatar.output_directory, self.name) )


    def assemble_cmd_line(self):
        if isfile(self.executable + self._arch.qemu_name):
            executable_name = [self.executable + self._arch.qemu_name]
        elif isfile(self.executable):
            executable_name = [self.executable]
        else:
            raise Exception("Executable for %s not found: %s" % (self.name,
                                                                 self.executable)
                            )

        machine = ["-machine", "configurable"]
        kernel = ["-kernel", self.qemu_config_file]
        gdb_option = ["-gdb", "tcp::" + str(self.gdb_port)]
        stop_on_startup = ["-S"]
        nographic = ["-nographic"]  # , "-monitor", "/dev/null"]
        qmp = ['-qmp', 'tcp:127.0.0.1:%d,server,nowait' % self.qmp_port]

        cmd_line = executable_name + machine + kernel + gdb_option \
               + stop_on_startup + self.additional_args + nographic + qmp

        if self.log_items is not None:
            if isinstance(self.log_items, str):
                log_items = ['-d', self.log_items]
            elif isinstance(self.log_items, list):
                log_items = ['-d', ','.join([i for i in self.log_items])]
            else:
                self.log.warn('Got unsupported type for log_items: %s' %
                              type(self.log_items))
                return cmd_line

            if self.log_file is not None:
                log_file = ['-D', '%s/%s' % (self.avatar.output_directory,
                                             self.log_file)]
            else:
                log_file = ['-D', '%s/%s_log.txt' %
                            (self.avatar.output_directory, self.name)]

            cmd_line += log_items + log_file

        return cmd_line


    def shutdown(self):
        if self._process is not None:
            self._process.terminate()
            self._process.wait()
            self._process = None
        super(QemuTarget, self).shutdown()

    def generate_qemu_config(self):
        """
        Generates the configuration passed to avatar-qemus configurable machine
        """
        conf_dict = self.avatar.generate_config()
        conf_dict['entry_address'] = self.entry_address
        if self.fw is not None:
            conf_dict['kernel'] = self.fw

        if self.system_clock_scale is not None:
            conf_dict['system_clock_scale'] = self.system_clock_scale

        for mr in conf_dict['memory_mapping']:
            if mr.get('qemu_name'):
                mr['properties'] = []
                mr['bus'] = 'sysbus'
                if mr['qemu_name'] == 'avatar-rmemory':
                    size_properties = {'type': 'uint32',
                                       'value': mr['size'],
                                       'name': 'size'}
                    mr['properties'].append(size_properties)
                    address_properties = {'type': 'uint64',
                                          'value': mr['address'],
                                          'name': 'address'}
                    mr['properties'].append(address_properties)
                    rx_queue_properties = {'type': 'string',
                                           'value': self._rmem_rx_queue_name,
                                           'name': 'rx_queue_name'}
                    mr['properties'].append(rx_queue_properties)
                    tx_queue_properties = {'type': 'string',
                                           'value': self._rmem_tx_queue_name,
                                           'name': 'tx_queue_name'}
                    mr['properties'].append(tx_queue_properties)

                elif mr.get('qemu_properties'):
                    if type(mr['qemu_properties']) == list:
                        mr['properties'] += mr['qemu_properties']
                    else:
                        mr['properties'].append(mr['qemu_properties'])
        del conf_dict['targets']
        return conf_dict

    @watch("TargetInit")
    def init(self, cmd_line=None):
        """
        Spawns a Qemu process and connects to it
        """

        if self.cpu_model is None:
            if hasattr(self._arch, 'cpu_model'):
                self.cpu_model = self.avatar.arch.cpu_model
            else:
                self.log.warning('No cpu_model specified - are you sure?')

        if cmd_line is None:
            cmd_line = self.assemble_cmd_line()

        self.avatar.save_config(file_name=self.qemu_config_file,
                                config=self.generate_qemu_config())

        with open("%s/%s_out.txt" % (self.avatar.output_directory, self.name)
                , "wb") as out, \
                open("%s/%s_err.txt" % (self.avatar.output_directory, self.name)
                    , "wb") as err:
            self._process = Popen(cmd_line, stdout=out, stderr=err)
        self.log.debug("QEMU command line: %s" % ' '.join(cmd_line))
        self.log.info("QEMU process running")
        self._connect_protocols()

    def _connect_protocols(self):
        """
        Internal routine to connect the various protocols to a running qemu
        """

        gdb = GDBProtocol(gdb_executable=self.gdb_executable,
                          arch=self.avatar.arch,
                          verbose=self.gdb_verbose,
                          additional_args=self.gdb_additional_args,
                          avatar=self.avatar, origin=self,
                          )
        qmp = QMPProtocol(self.qmp_port, origin=self)

        if 'avatar-rmemory' in [i[2].qemu_name for i in
                                self._memory_mapping.iter() if
                                hasattr(i[2], 'qemu_name')]:
            rmp = RemoteMemoryProtocol(self._rmem_tx_queue_name,
                                       self._rmem_rx_queue_name,
                                       self.avatar.queue, self)
        else:
            rmp = None

        self.protocols.set_all(gdb)
        self.protocols.monitor = qmp
        self.protocols.remote_memory = rmp

        if gdb.remote_connect(port=self.gdb_port) and qmp.connect():
            self.log.info("Connected to remote target")
        else:
            self.log.warning("Connection to remote target failed")
        if rmp:
            rmp.connect()
        self.wait()
