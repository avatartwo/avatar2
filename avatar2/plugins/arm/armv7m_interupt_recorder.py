import logging
from types import MethodType

import avatar2
from avatar2.archs import ARMV7M
from avatar2.protocols.armv7_interrupt_recording import ARMV7InterruptRecordingProtocol
from avatar2.targets import OpenOCDTarget
from avatar2.watchmen import AFTER

from avatar2.message import TargetInterruptEnterMessage, TargetInterruptExitMessage

from avatar2.watchmen import watch


def add_protocols(self: avatar2.Avatar, **kwargs):
    target = kwargs['watched_target']
    assert isinstance(target, OpenOCDTarget), "Interrupt-Recorder only works with OpenOCDTarget"
    logging.getLogger("avatar").info(f"Attaching ARMv7 Interrupt-Recorder protocol to {target}")

    target.protocols.interrupts = ARMV7InterruptRecordingProtocol(target.avatar, target)

    # We want to remove the decorators around the read_memory function of
    # this target, to allow reading while it is running (thanks oocd)
    target.read_memory = MethodType(lambda t, *args, **kwargs:
                                    t.protocols.memory.read_memory(
                                        *args, **kwargs), target
                                    )


@watch('TargetInterruptEnter')
def _handle_interrupt_enter(self: avatar2.Avatar, message: TargetInterruptEnterMessage):
    pass


@watch('TargetInterruptExit')
def _handle_interrupt_exit(self: avatar2.Avatar, message: TargetInterruptExitMessage):
    pass


def enable_interrupt_recording(self, from_target):
    assert isinstance(from_target, OpenOCDTarget), "Interrupt-Recorder only works with OpenOCDTarget"
    self._hardware_target = from_target

    # Also, let's use openocd as protocol for register and memory
    self._hardware_target.protocols.memory = self._hardware_target.protocols.monitor
    self._hardware_target.protocols.registers = self._hardware_target.protocols.monitor

    self._hardware_target.protocols.interrupts.enable_interrupt_recording()
    isr_addr = self._hardware_target.protocols.interrupts._monitor_stub_isr - 1
    self.log.info("ISR is at %#08x" % isr_addr)

    self._handle_interrupt_enter = MethodType(_handle_interrupt_enter, self)
    self._handle_interrupt_exit = MethodType(_handle_interrupt_exit, self)

    self.message_handlers.update({
        TargetInterruptEnterMessage: lambda m: None,  # Handled in the fast queue, just ignore in the main message queue
        TargetInterruptExitMessage: lambda m: None,  # Handled in the fast queue, just ignore in the main message queue
    })
    self.fast_queue_listener.message_handlers.update({
        TargetInterruptEnterMessage: self._handle_interrupt_enter,
        TargetInterruptExitMessage: self._handle_interrupt_exit,
    })


def load_plugin(avatar: avatar2.Avatar):
    if avatar.arch != ARMV7M:
        avatar.log.error("Tried to load armv7-m interrupt-recorder plugin " +
                         "with mismatching architecture")

    avatar.enable_interrupt_recording = MethodType(enable_interrupt_recording, avatar)

    avatar.watchmen.add_watchman('TargetInit', when=AFTER, callback=add_protocols)
