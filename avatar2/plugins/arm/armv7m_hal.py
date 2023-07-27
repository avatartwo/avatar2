import logging
from types import MethodType

import avatar2
from avatar2 import QemuTarget
from avatar2.archs import ARMV7M
from avatar2.protocols.armv7_hal_caller import ARMV7HALCallerProtocol
from avatar2.protocols.qemu_armv7_hal_caller import QemuARMV7HALCallerProtocol
from avatar2.targets import OpenOCDTarget
from avatar2.watchmen import AFTER

from avatar2.message import HALExitMessage, HALEnterMessage

from avatar2.watchmen import watch


class HALCaller:

    def __init__(self, avatar, config):
        self.avatar = avatar
        self.hardware_target = None
        self.virtual_target = None
        self.functions = config['functions']
        self.log = logging.getLogger(f'{avatar.log.name}.plugins.{self.__class__.__name__}')

    @watch('HALEnter')
    def hal_enter(self, message: HALEnterMessage):
        self.log.warning(f"hal_enter called with {message}")
        self.hardware_target.protocols.interrupts.pause()
        for arg in message.args:
            if arg.needs_transfer:
                self.log.info(f"Transferring argument of size {arg.size} at address 0x{arg.value:x}")
                arg_data = self.virtual_target.read_memory(arg.value, size=1, num_words=arg.size)
                self.hardware_target.write_memory(arg.value, size=1, value=arg_data, num_words=arg.size)
        self.hardware_target.protocols.hal.hal_call(message.function_addr, message.args, message.return_address)

    @watch('HALExit')
    def hal_exit(self, message: HALExitMessage):
        self.log.warning(f"hal_exit called with return val {message.return_val} to 0x{message.return_address:x}")
        self.hardware_target.protocols.interrupts.resume()
        self.virtual_target.protocols.hal.handle_hal_return(message)


    def enable_hal_calling(self):
        assert isinstance(self.hardware_target, OpenOCDTarget), "HAL-Caller `hardware_target` must be OpenOCDTarget"
        assert isinstance(self.virtual_target, QemuTarget), "HAL-Caller `virtual_target` must be QemuTarget"

        self.hardware_target.protocols.hal.enable()
        self.virtual_target.protocols.hal.enable(self.functions)

        self.avatar.message_handlers.update({
            HALEnterMessage: lambda m: None,  # Handled in the fast queue, just ignore in the main message queue
            HALExitMessage: lambda m: None,  # Handled in the fast queue, just ignore in the main message queue
        })
        self.avatar.fast_queue_listener.message_handlers.update({
            HALEnterMessage: self.hal_enter,
            HALExitMessage: self.hal_exit,
        })


def add_protocols(self: avatar2.Avatar, **kwargs):
    target = kwargs['watched_target']
    if isinstance(target, OpenOCDTarget):
        logging.getLogger("avatar").info(f"Attaching ARMv7 Interrupt-Recorder protocol to {target}")
        target.protocols.hal = ARMV7HALCallerProtocol(target.avatar, target)
        self._plugin_hal_caller.hardware_target = target

    elif isinstance(target, QemuTarget):
        logging.getLogger("avatar").info(f"Attaching ARMv7 Interrupt-Recorder protocol to {target}")
        target.protocols.hal = QemuARMV7HALCallerProtocol(target.avatar, target)
        self._plugin_hal_caller.virtual_target = target
    else:
        logging.getLogger("avatar").warning(f"Unsupported target {target}")


def load_plugin(avatar: avatar2.Avatar, config):
    if avatar.arch not in ARMV7M:
        avatar.log.error("Tried to load armv7-m hal-caller plugin " +
                         "with mismatching architecture")
    avatar._plugin_hal_caller = HALCaller(avatar, config)
    avatar.enable_hal_calling = MethodType(HALCaller.enable_hal_calling, avatar._plugin_hal_caller)

    avatar.watchmen.add_watchman('TargetInit', when=AFTER, callback=add_protocols)
