from avatar2.installer.config import AvatarConfig
import distutils
from os import environ
from re import sub

class Architecture(object):
    
    @staticmethod 
    def _resolve_executable(exec_name):
        """
        Resolves the name of the executable for the endpoint, using the config
        file generated by avatar2's installer
        Convienently enough, this config already checks whether the executable
        is installed on the system
        """

        env_var_name = 'AVATAR2_%s_EXECUTABLE' % sub(r'avatar-|\W\(.*\)',
                                                     '', exec_name).upper()
        env_exec = environ.get( env_var_name )
        if env_exec is not None:
            target_path = distutils.spawn.find_executable(env_exec)
        else:
            target_path = AvatarConfig().get_target_path(exec_name)
        if target_path is None:
            raise Exception(("Couldn't find executable for %s\n"
                             "Have you tried running the avatar2-installer "
                             "(python -m avatar2.installer) or setting the %s "
                             "environment variable?" % (exec_name, env_var_name)
                            ))
        return target_path

    @staticmethod
    def resolve(exec_name):
        """
        This wrapper around _resolve_executable allows us to have targets
        only resolved when needed, and not when the arch-class gets imported
        """
        return staticmethod(lambda : Architecture._resolve_executable(exec_name))



    @staticmethod
    def init(avatar):
        pass
    
    registers = None
    special_registers = {}
    sr_name = None
