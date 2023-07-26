from enum import Enum
from threading import Thread, Event
import logging
from time import sleep
from types import MethodType

from avatar2.targets import TargetStates
from avatar2.message import TargetInterruptEnterMessage, TargetInterruptExitMessage, BreakpointHitMessage, \
    HALEnterMessage, HALExitMessage
from avatar2.protocols.openocd import OpenOCDProtocol
from avatar2.watchmen import AFTER, BEFORE


class QemuARMV7HALCallerProtocol():
    def __init__(self, avatar, origin):
        self.avatar = avatar
        self._avatar_fast_queue = avatar.fast_queue
        self.target = origin
        self.functions: [(int, [int])] = []

        self.log = logging.getLogger(f'{avatar.log.name}.protocols.{self.__class__.__name__}')
        self.log.info(f"QemuARMV7HALCallerProtocol initialized")

    def __del__(self):
        self.shutdown()

    def shutdown(self):
        pass

    def connect(self):
        pass

    def enable(self, functions: [(int, [int])]):
        try:
            self.log.info(f"Enabling QEmu HAL catching")
            self.functions = functions
            for func_addr, args in self.functions:
                self.log.info(f"Setting breakpoint at {func_addr}")
                self.target.set_breakpoint(func_addr)

            self.avatar.watchmen.add_watchman('BreakpointHit', AFTER, self._handle_breakpoint)

            self.log.info(f"Starting QEmu HAL catching thread")
        except:
            self.log.exception("Error starting QemuARMV7HALCallerProtocol")

    def _handle_breakpoint(self, avatar, message: BreakpointHitMessage, *args, **kwargs):
        self.log.debug(f"_handle_breakpoint got additional {args}, {kwargs}")
        if message.origin != self.target:
            return
        for func_addr, args in self.functions:
            if message.address == func_addr:
                return_address = self.target.regs.lr
                self.dispatch_message(HALEnterMessage(self.target, function_addr=func_addr, args=args,
                                                      return_address=return_address))
                return

    def handle_hal_return(self, message: HALExitMessage):
        self.target.regs.r0 = message.return_val
        self.target.regs.pc = message.return_address
        self.target.cont()

    def dispatch_message(self, message):
        self._avatar_fast_queue.put(message)
