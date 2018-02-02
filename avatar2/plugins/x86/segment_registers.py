from types import MethodType
from threading import Event
from enum import Enum
import os

from avatar2.watchmen import AFTER, BEFORE, watch
from avatar2 import TargetStates, GDBTarget, action_valid_decorator_factory

avatar_library = os.path.dirname(os.path.abspath(__file__)) + \
                    '/../../../segment_registers.so'

def read_fs(avatar, register, **kwargs):
    target = kwargs['watched_target']
    if not isinstance(target, GDBTarget):
        return
    if register != "fs":
        return
    target.log.debug("Attempt to read the FS register")
    ret = kwargs['watched_target']

    scratch =  target.avatar.arch.scratch_registers
    savedrip = target.regs.rip
    saved_regs = [target.read_register(r) for r in scratch]

    ret, _ = target.protocols.execution.console_command(
        "set $rip = avatar_get_fs"
    )


    if not ret:
        target.log.error("Attempted to read FS from GDBTarget %s but failed" +
                         " to execute the injected code. " +
                         "Did you LDpreload the library in the process " +
                         "address space?")
        return

    # very fragile parsing, we should optimize this
    disasm = target.protocols.execution.console_command('disas')[1].split('\n')
    ret_addr =  disasm[-2].split()[0]

    target.protocols.execution.set_gdb_variable('scheduler-locking', 'on')

    target.protocols.execution.console_command('tbreak *%s' % ret_addr)
    target.cont()
    target.wait()
    fs = target.regs.rax
    target.log.debug("Read FS value. FS = 0x%x" % fs)

    target.regs.rip = savedrip
    [target.write_register(r, v) for r,v in zip(scratch, saved_regs)]

    target.protocols.execution.set_gdb_variable('scheduler-locking', 'replay')

    return fs

def preload_avatar_library(avatar, **kwargs):
    target = kwargs['watched_target']
    if not isinstance(target, GDBTarget):
        return
    target.log.debug("Setting the LD_PRELOAD=%s" % avatar_library)
    cmd = "set environ LD_PRELOAD=%s" % avatar_library
    target.protocols.execution.console_command(cmd)

def load_plugin(avatar):
    avatar.log.debug("Loading segment register loader plugin")
    avatar.watchmen.add_watchman('TargetRegisterRead', when='after',
                                 callback=read_fs, overwrite_return=True)

    avatar.watchmen.add_watchman('TargetInit', when=AFTER,
                                 callback=preload_avatar_library)
