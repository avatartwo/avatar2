import logging
import queue
from threading import Thread, Event

from avatar2.message import BreakpointHitMessage, HALEnterMessage, HALExitMessage
from avatar2.plugins.arm import FuncArg
from avatar2.watchmen import AFTER

CMD_CONT = 0


class QemuARMV7HALCallerProtocol(Thread):
    def __init__(self, avatar, origin):
        self.avatar = avatar
        self._avatar_fast_queue = avatar.fast_queue
        self._close = Event()
        self._closed = Event()
        self.target = origin
        self.functions: [(int, [FuncArg])] = []
        self.command_queue = queue.Queue()

        self.log = logging.getLogger(f'{avatar.log.name}.protocols.{self.__class__.__name__}')
        Thread.__init__(self, daemon=True, name=f"Thread-{self.__class__.__name__}")
        self.log.info(f"QemuARMV7HALCallerProtocol initialized")

    def __del__(self):
        self.shutdown()

    def shutdown(self):
        if self.is_alive() is True:
            self.stop()

    def connect(self):
        pass

    def enable(self, functions: [(int, [FuncArg])]):
        try:
            self.log.info(f"Enabling QEmu HAL catching")
            self.functions = functions
            for func_addr, args in self.functions:
                self.log.info(f"Setting breakpoint at 0x{func_addr:x}")
                self.target.set_breakpoint(func_addr)

            self.avatar.watchmen.add_watchman('BreakpointHit', AFTER, self._handle_breakpoint)

            self.start()
            self.log.info(f"Starting QEmu HAL catching thread")
        except:
            self.log.exception("Error starting QemuARMV7HALCallerProtocol")

    def _handle_breakpoint(self, avatar, message: BreakpointHitMessage, *args, **kwargs):
        if message.origin != self.target:
            return
        for func_addr, args in self.functions:
            if message.address == func_addr:
                self.log.info(f"Dispatching HALEnterMessage for function at 0x{func_addr:x}")
                return_address = self.target.regs.lr
                self.dispatch_message(HALEnterMessage(self.target, function_addr=func_addr, args=args,
                                                      return_address=return_address))
                return

    def handle_hal_return(self, message: HALExitMessage):
        self.log.info(
            f"Continuing QEmu, injecting return value {message.return_val} and continuing at 0x{message.return_address:x}")
        self.target.regs.r0 = message.return_val
        self.target.regs.pc = message.return_address
        self.command_queue.put((CMD_CONT,))

    def run(self):
        self.log.info("Starting QemuARMV7HALCallerProtocol thread")

        try:
            while not (self.avatar._close.is_set() or self._close.is_set()):
                try:
                    command = self.command_queue.get(timeout=1.0)
                    if command[0] == CMD_CONT:
                        self.target.cont()
                    else:
                        self.log.error(f"Unknown command {command[0]}")
                    self.command_queue.task_done()
                except queue.Empty:
                    continue

        except:
            self.log.exception("Error processing QemuARMV7HALCallerProtocol thread")
            self._closed.set()
        self.log.debug("QemuARMV7HALCallerProtocol thread exiting...")
        self._closed.set()

    def dispatch_message(self, message):
        self._avatar_fast_queue.put(message)

    def stop(self):
        """Stops the listening thread. Useful for teardown of the target"""
        self._close.set()
        self._closed.wait()
