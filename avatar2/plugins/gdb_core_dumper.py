from types import MethodType
import os

from avatar2.watchmen import AFTER, BEFORE, watch
from avatar2 import TargetStates, GDBTarget


def dump_core_target(target, *args, **kwargs):
    """
    Stub method for compatibility to be able to call dump_core on the
    target object.
    """
    return dump_core(target.avatar, target, *args, **kwargs)


def dump_core(avatar, target, core_filename=""):
    """
    Create a core dump for the given GDB target
    :param core_filename: Filename to output core dump file to, can be absolute path or filename (to output to avatar's output directory); passing None causes the core dump to use default GDB naming scheme and is placed in the output directory.
    :return:              Tuple of return value, console output
    """
    if not isinstance(target, GDBTarget):
        raise TypeError("Core dumps can only be generated from GDBTargets")

    if core_filename == "":
        # If no core_filename name specifed, put file in output directory with
        # default GDB naming scheme.
        pid = 9999
        tokens = target.protocols.execution.console_command('info inferior')[1].split("\n")[2].split()
        for i in range(len(tokens)):
            if tokens[i] == "process":
                pid = tokens[i+1]
        
        # Return return value (True of False), and
        # output string of the console command.
        ret, output = target.protocols.execution.console_command('generate-core-file %s/core.%s' % (avatar.output_directory, pid))
        return ret, output
    elif os.path.dirname(core_filename) == "":
        # If only file basename provided, put core dump file in output directory.
        # Return return value (True of False), and
        # output string of the console command.
        return target.protocols.execution.console_command('generate-core-file %s/%s' % (avatar.output_directory, core_filename))
    elif os.path.isdir(os.path.dirname(core_filename)) == True:
        # Return return value (True of False), and
        # output string of the console command.
        return target.protocols.execution.console_command('generate-core-file %s' % core_filename)
    else:
        return False, ""


def add_methods(target):
    target.dump_core = MethodType(dump_core_target, target)


def target_added_callback(avatar, *args, **kwargs):
    target = kwargs["watched_return"]
    add_methods(target)


def load_plugin(avatar):
    avatar.watchmen.add_watchman(
        "AddTarget", when="after", callback=target_added_callback
    )
    avatar.dump_core = MethodType(dump_core, avatar)
    for target in avatar.targets.values():
        add_methods(target)
