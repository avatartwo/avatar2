import logging
from datetime import datetime
from types import MethodType

import avatar2
from avatar2.archs import ARMV7M
from avatar2.protocols.armv7_interrupt_recording import ARMv7MInterruptRecordingProtocol
from avatar2.targets import OpenOCDTarget
from avatar2.watchmen import AFTER

from avatar2.message import TargetInterruptEnterMessage, TargetInterruptExitMessage

from avatar2.watchmen import watch


class InterruptRecorderPlugin:

    def __init__(self, avatar):
        self.avatar = avatar
        self.hardware_target = None
        self.trace = []
        self.log = logging.getLogger(f'{avatar.log.name}.plugins.{self.__class__.__name__}')

    @watch('TargetInterruptEnter')
    def _handle_interrupt_enter(self, message: TargetInterruptEnterMessage):
        interrupt_num = message.interrupt_num
        self.trace.append(
            {'id': message.id, 'event': 'enter', 'interrupt_num': interrupt_num,
             'timestamp': datetime.now().isoformat()})

    @watch('TargetInterruptExit')
    def _handle_interrupt_exit(self, message: TargetInterruptExitMessage):
        interrupt_num = message.interrupt_num
        self.trace.append(
            {'id': message.id, 'event': 'exit', 'interrupt_num': interrupt_num,
             'timestamp': datetime.now().isoformat()})

    def enable_interrupt_recording(self):
        assert self.hardware_target is not None, "Interrupt-Recorder can only be enabled after a hardware target is set"
        # Also, let's use openocd as protocol for register and memory
        self.hardware_target.protocols.memory = self.hardware_target.protocols.monitor
        self.hardware_target.protocols.registers = self.hardware_target.protocols.monitor

        self.hardware_target.protocols.interrupts.enable_interrupt_recording()

        self.avatar.fast_queue_listener.message_handlers.update({
            TargetInterruptEnterMessage: self._handle_interrupt_enter,
            TargetInterruptExitMessage: self._handle_interrupt_exit,
        })


def add_protocols(self: avatar2.Avatar, **kwargs):
    target = kwargs['watched_target']
    if not isinstance(target, OpenOCDTarget):
        logging.getLogger('avatar').warning(f"Interrupt-Recorder only works with OpenOCDTarget but got {target}")
        return
    logging.getLogger("avatar").info(f"Attaching ARMv7 Interrupt-Recorder protocol to {target}")

    target.protocols.interrupts = ARMv7MInterruptRecordingProtocol(target.avatar, target)
    self._plugin_interrupt_recorder.hardware_target = target

    # We want to remove the decorators around the read_memory function of
    # this target, to allow reading while it is running (thanks OpenOCD)
    target.read_memory = MethodType(lambda t, *args, **kwargs:
                                    t.protocols.memory.read_memory(
                                        *args, **kwargs), target
                                    )


def load_plugin(avatar: avatar2.Avatar):
    if avatar.arch not in ARMV7M:
        avatar.log.error("Tried to load armv7-m interrupt-recorder plugin " +
                         "with mismatching architecture")
    avatar._plugin_interrupt_recorder = InterruptRecorderPlugin(avatar)
    avatar.enable_interrupt_recording = MethodType(InterruptRecorderPlugin.enable_interrupt_recording,
                                                   avatar._plugin_interrupt_recorder)

    avatar.watchmen.add_watchman('TargetInit', when=AFTER, callback=add_protocols)
