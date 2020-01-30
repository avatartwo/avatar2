from threading import Thread
from avatar2.targets import PandaTarget



class PyPandaTarget(PandaTarget):
    '''
    The pypanda target is a PANDA target, but uses pypanda to run the framework.

    '''
    def __init__(self, *args, **kwargs):
        try:
            import panda
        except ImportError:
            raise RuntimeError(("PyPanda could not be found! for installation, "
                    "please follow the steps at https://github.com/"
                    "panda-re/panda/blob/master/panda/pypanda/docs/USAGE.md"))

        super(PyPandaTarget, self).__init__(*args, **kwargs)

        self.pypanda = None
        self._thread = None
    
    def shutdown(self):
        if self._thread.is_alive():
            self.pypanda.end_analysis()


    def init(self, **kwargs):
        from panda import Panda

        arch = self.avatar.arch.gdb_name # for now, gdbname and panda-name match
        args = self.assemble_cmd_line()[1:]
        


        self.avatar.save_config(file_name=self.qemu_config_file,
                                config=self.generate_qemu_config())


        self.pypanda = Panda(arch=arch, extra_args=args, **kwargs)
        
        # pypanda.run() is blocking, hence we run it in a seperate thread
        self._thread = Thread(target=self.pypanda.run, daemon=True)
        self._thread.start()
        
        self._connect_protocols()
