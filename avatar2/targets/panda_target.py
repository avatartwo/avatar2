from subprocess import Popen, PIPE
import json
import intervaltree

from avatar2.targets import Target,action_valid_decorator_factory
from avatar2.targets import TargetStates
from avatar2.targets import QemuTarget
from avatar2.protocols.gdb import GDBProtocol
from avatar2.protocols.remote_memory import RemoteMemoryProtocol

import logging


class PandaTarget(QemuTarget):

    def init(self, *args, **kwargs):
        super(self.__class__, self).init(*args, **kwargs)
        #self._monitor_protocol = self._exec_protocol

    @action_valid_decorator_factory(TargetStates.STOPPED, '_monitor_protocol')
    def begin_record(self, record_name):
        """
        Starts recording the execution in PANDA

        :param record_name:   The name of the record file 
        """
        filename = "%s/%s" % (self.avatar.output_directory, record_name)
        return self._monitor_protocol.execute_command('begin_record',
                                                      {'file_name': filename})
        #self._monitor_protocol._sync_request('monitor begin_record "%s"'
         #                                    % filename, 'done')

    @action_valid_decorator_factory(TargetStates.STOPPED, '_monitor_protocol')
    def end_record(self):
        """
        Stops recording the execution in PANDA
        """
        return self._monitor_protocol.execute_command('end_record')
        #self._monitor_protocol._sync_request('monitor end_record', 'done')

    @action_valid_decorator_factory(TargetStates.STOPPED, '_monitor_protocol')
    def begin_replay(self, replay_name):
        """
        Starts replaying a captured replay

        :param replay_name: The name of the file to be replayed
        """
        self._monitor_protocol.execute_command('begin_replay',
                                               {'file_name': replay_name})
        self.cont()
    

    @action_valid_decorator_factory(TargetStates.STOPPED, '_monitor_protocol')
    def end_replay(self):
        """
        Stops a current ongoing replay
        """
        return self._monitor_protocol.execute_command('end_replay')

    @action_valid_decorator_factory(TargetStates.STOPPED, '_monitor_protocol')
    def load_plugin(self, plugin_name, plugin_args=None, file_name=None ):
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

        return self._monitor_protocol.execute_command('load_plugin', args_dict)
    
    @action_valid_decorator_factory(TargetStates.STOPPED, '_monitor_protocol')
    def unload_plugin(self, plugin_name):
        """
        Unloads a PANDA plugin

        :param plugin_name: The name of the plugin to be unloaded
        :return: True if the requested plugin was present
        """
        full_plugin_name = 'panda_%s.so' % plugin_name
        for plugin_dict in self.list_plugins():
            if plugin_dict['name'] == full_plugin_name:
                self._monitor_protocol.execute_command('unload_plugin',
                                             {'index' : plugin_dict['index']})
                return True
        return False



   
    @action_valid_decorator_factory(TargetStates.STOPPED, '_monitor_protocol')
    def list_plugins(self):
        """
        Lists the laoded PANDA plugins

        :return: a list with the loaded panda_plugins
        """
        return self._monitor_protocol.execute_command('list_plugins')


