from avatar2.targets import QemuTarget
from avatar2.targets import TargetStates
from avatar2.targets import action_valid_decorator_factory


class PandaTarget(QemuTarget):
    def __init__(self, *args, **kwargs):
        super(PandaTarget, self).__init__(*args, **kwargs)

        executable = kwargs.get('executable')
        self.executable = (executable if executable is not None
                           else self._arch.get_panda_executable())

        # self.protocols.monitor = self.protocols.execution

    @action_valid_decorator_factory(TargetStates.STOPPED, 'monitor')
    def begin_record(self, record_name):
        """
        Starts recording the execution in PANDA

        :param record_name:   The name of the record file
        """
        filename = "%s/%s" % (self.avatar.output_directory, record_name)
        return self.protocols.monitor.execute_command('begin_record',
                                                      {'file_name': filename})
        # self.protocols.monitor._sync_request('monitor begin_record "%s"'
        #                                    % filename, 'done')

    @action_valid_decorator_factory(TargetStates.STOPPED, 'monitor')
    def end_record(self):
        """
        Stops recording the execution in PANDA
        """
        return self.protocols.monitor.execute_command('end_record')
        # self.protocols.monitor._sync_request('monitor end_record', 'done')

    @action_valid_decorator_factory(TargetStates.STOPPED, 'monitor')
    def begin_replay(self, replay_name, cont=True):
        """
        Starts replaying a captured replay

        :param replay_name: The name of the file to be replayed
        :param cont: Whether execution shall automatically be resumed (default True)
        """
        self.protocols.monitor.execute_command('begin_replay',
                                               {'file_name': replay_name})
        if cont is True:
            self.cont()

    @action_valid_decorator_factory(TargetStates.STOPPED, 'monitor')
    def end_replay(self):
        """
        Stops a current ongoing replay
        """
        return self.protocols.monitor.execute_command('end_replay')

    @action_valid_decorator_factory(TargetStates.STOPPED, 'monitor')
    def load_plugin(self, plugin_name, plugin_args=None, file_name=None):
        """
        Loads a PANDA plugin

        :param plugin_name: The name of the plugin to be loaded
        :param plugin_args: Arguments to be passed to the plugin,
                            aseperated by commas
        :param file_name:   Absolute path to the plugin shared object file,
                            in case that the default one should not be used
        """

        args_dict = {'plugin_name': plugin_name}
        if plugin_args:
            args_dict['plugin_args'] = plugin_args
        if file_name:
            args_dict['file_name'] = file_name

        return self.protocols.monitor.execute_command('load_plugin', args_dict)

    @action_valid_decorator_factory(TargetStates.STOPPED, 'monitor')
    def unload_plugin(self, plugin_name):
        """
        Unloads a PANDA plugin

        :param plugin_name: The name of the plugin to be unloaded
        :return: True if the requested plugin was present
        """
        full_plugin_name = 'panda_%s.so' % plugin_name
        for plugin_dict in self.list_plugins():
            if plugin_dict['name'] == full_plugin_name:
                self.protocols.monitor.execute_command('unload_plugin',
                                                       {'index': plugin_dict['index']})
                return True
        return False

    @action_valid_decorator_factory(TargetStates.STOPPED, 'monitor')
    def list_plugins(self):
        """
        Lists the laoded PANDA plugins

        :return: a list with the loaded panda_plugins
        """
        return self.protocols.monitor.execute_command('list_plugins')
