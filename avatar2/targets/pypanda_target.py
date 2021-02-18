from threading import Thread
from time import sleep
from avatar2.targets import PandaTarget

from ..watchmen import watch
from .target import action_valid_decorator_factory, TargetStates


class PyPandaTarget(PandaTarget):
    '''
    The pypanda target is a PANDA target, but uses pypanda to run the framework.

    '''
    def __init__(self, *args, **kwargs):
        try:
            import pandare
        except ImportError:
            raise RuntimeError(("PyPanda could not be found! for installation, "
                    "please follow the steps at https://github.com/"
                    "panda-re/panda/blob/master/panda/pypanda/docs/USAGE.md"))

        super(PyPandaTarget, self).__init__(*args, **kwargs)

        self.cb_ctx  = 0
        self.pypanda = None
        self._thread = None

    def shutdown(self):


        if self._thread.is_alive():
            self.protocols.execution.remote_disconnect()
            self.pypanda.end_analysis()

            # Wait for shutdown
            while self._thread.is_alive():
                sleep(.01)


    @watch('TargetInit')
    def init(self, **kwargs):
        from pandare import Panda

        arch = self.avatar.arch.qemu_name
        args = self.assemble_cmd_line()[1:]



        self.avatar.save_config(file_name=self.qemu_config_file,
                                config=self.generate_qemu_config())


        self.pypanda = Panda(arch=arch, extra_args=args, **kwargs)


        # adjust panda's signal handler to avatar2-standard
        def SigHandler(SIG,a,b):
            if self.state == TargetStates.RUNNING:
                self.stop()
                self.wait()

            self.avatar.sigint_handler()



        self.pypanda.setup_internal_signal_handler(signal_handler=SigHandler)

        self._thread = Thread(target=self.pypanda.run, daemon=True)
        self._thread.start()

        self._connect_protocols()



    def register_callback(self, callback, function, name=None, enabled=True,
                          procname=None):
        pp = self.pypanda

        if hasattr(pp.callback, callback) is False:
            raise Exception("Callback %s not found!" % callback)
        cb = getattr(pp.callback, callback)

        if name == None:
            name = 'avatar_cb_%d' % self.cb_ctx
        self.cb_ctx += 1

        pp.register_callback(cb, cb(function), name, enabled=enabled,
                             procname=procname)

        return name

    def disable_callback(self, name):
        pp = self.pypanda
        pp.disable_callback(name)

    def enable_callback(self, name):
        pp = self.pypanda
        pp.enable_callback(name)


    @watch('TargetReadMemory')
    @action_valid_decorator_factory(TargetStates.STOPPED, 'memory')
    def read_memory(self, address, size, num_words=1, raw=False):
        if raw == False:
            return self.protocols.memory.read_memory(address, size, num_words)
        else:
            return self.pypanda.physical_memory_read(address,size*num_words)


    @watch('TargetWriteMemory')
    @action_valid_decorator_factory(TargetStates.STOPPED, 'memory')
    def write_memory(self, address, size, value, num_words=1, raw=False):
        if raw == False:
            return self.protocols.memory.write_memory(address, size, value, num_words=num_words)
        else:
            return self.pypanda.physical_memory_write(address, value)



    def delete_callback(self, name):
        return self.pypanda.delete_callback(name)

