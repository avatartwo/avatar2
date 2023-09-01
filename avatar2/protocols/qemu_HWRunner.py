import logging
import queue
from threading import Thread, Event

from avatar2.message import BreakpointHitMessage, HALEnterMessage, HALExitMessage
from avatar2.plugins.arm.hal import HALFunction
from avatar2.watchmen import AFTER

CMD_CONT = 0


class QemuARMv7MHWRunnerProtocol(Thread):
    def __init__(self, avatar, origin):
        self.avatar = avatar
        self._avatar_fast_queue = avatar.fast_queue
        self._close = Event()
        self._closed = Event()
        self.target = origin
        self.functions: [HALFunction] = []
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

    def enable(self, functions: [HALFunction]):
        try:
            self.log.info(f"Enabling QEmu HAL catching")
            self.functions = functions
            for func in self.functions:
                self.log.info(f"Setting breakpoint at 0x{func.address:x}")
                self.target.set_breakpoint(func.address)

            self.avatar.watchmen.add_watchman('BreakpointHit', AFTER, self._handle_breakpoint)

            self.start()
            self.log.info(f"Starting QEmu HAL catching thread")
        except:
            self.log.exception("Error starting QemuARMV7HALCallerProtocol")

    def _handle_breakpoint(self, avatar, message: BreakpointHitMessage, *args, **kwargs):
        if message.origin != self.target:
            return
        for function in self.functions:
            if message.address == function.address:
                self.log.info(f"Dispatching HALEnterMessage for function at 0x{function.address:x}")
                return_address = self.target.regs.lr
                self._dispatch_message(HALEnterMessage(self.target, function, return_address=return_address))
                return

    def handle_func_return(self, message: HALExitMessage):
        self.log.info(
            f"Continuing QEmu, injecting return value {message.return_val} and continuing at 0x{message.return_address:x}")
        if message.function.return_args is None or message.function.return_args[0] is not None:
            self.target.regs.r0 = message.return_val
        else:
            self.log.warning(f"Return value of function is void, skipping return value injection")
        self.target.regs.pc = message.return_address
        self.continue_target()

    def continue_target(self):
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

    def _dispatch_message(self, message):
        self._avatar_fast_queue.put(message)

    def stop(self):
        """Stops the listening thread. Useful for teardown of the target"""
        self._close.set()
        self._closed.wait()
