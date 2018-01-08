from types import MethodType
from threading import Event
from enum import Enum
import os

from avatar2.watchmen import AFTER, BEFORE, watch
from avatar2 import TargetStates, GDBTarget, action_valid_decorator_factory

avatar_library = os.path.dirname(os.path.abspath(__file__)) + "/avatar_fs.so"

def read_fs(avatar, register, **kwargs):
    target = kwargs['watched_target']
    if not isinstance(target, GDBTarget):
        return
    if register != "fs":
        return
    target.log.debug("Attempt to read the FS register")
    ret = kwargs['watched_target']
    rip = target.regs.rip
    ret, _ = target.protocols.execution.console_command(
        "set $rip = avatar_get_fs"
    )
    _, library_end = target.protocols.execution.console_command(
        'printf "0x%lx", avatar_get_fs_end'
    )
    if not ret:
        target.log.error("Attempted to read FS from GDBTarget %s but failed" +
                         " to execute the injected code. " +
                         "Did you LDpreload the library in the process " +
                         "address space?")
        return
    target.protocols.execution.set_gdb_variable('scheduler-locking', 'on')
    end_address = long(library_end, 16)
    rax = target.regs.rax
    while target.regs.rip != end_address:
        target.step()
    fs = target.regs.rax
    target.log.debug("Read FS value. FS = 0x%x" % fs)
    target.regs.rip = rip
    target.regs.rax = rax
    target.protocols.execution.set_gdb_variable('scheduler-locking', 'replay')

    return fs

@action_valid_decorator_factory(TargetStates.INITIALIZED, 'execution')
def preload_avatar_library(self):
    self.log.debug("Setting the LD_PRELOAD=%s" % avatar_library)
    cmd = "set environ LD_PRELOAD=%s" % avatar_library
    self.protocols.execution.console_command(cmd)

def load_plugin(avatar):
    avatar.log.debug("Loading FS register loader plugin")
    avatar.watchmen.add_watchman('TargetRegisterRead', when='after',
                                 callback=read_fs, overwrite_return=True)
    for _, target in avatar.get_targets():
        if isinstance(target, GDBTarget):
            target.preload_avatar_library = MethodType(preload_avatar_library,
                                                       target)
