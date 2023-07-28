import queue
from threading import Thread, Event
import logging

from avatar2 import TargetStates
from avatar2.message import BreakpointHitMessage, HALExitMessage
from avatar2.plugins.arm.hal import HALFunction
from avatar2.watchmen import AFTER

CMD_HAL_CALL = 0
CMD_CONT = 1


class ARMV7HALCallerProtocol(Thread):

    def __init__(self, avatar, origin):
        self.avatar = avatar
        self._avatar_fast_queue = avatar.fast_queue
        self._close = Event()
        self._closed = Event()
        self.target = origin
        self.functions = []
        self.command_queue = queue.Queue()

        self._stub_base = None
        self._stub_func_ptr = None
        self._stub_entry = None
        self._stub_end = None

        self.current_hal_call = None
        self.return_after_hal = None

        self.log = logging.getLogger(f'{avatar.log.name}.protocols.{self.__class__.__name__}')
        Thread.__init__(self, daemon=True, name=f"Thread-{self.__class__.__name__}")
        self.log.info(f"ARMV7HALCallerProtocol initialized")

    def __del__(self):
        self.shutdown()

    def shutdown(self):
        if self.is_alive() is True:
            self.stop()

    def connect(self):
        pass

    def enable(self, functions: [HALFunction]):
        self.functions = functions
        try:
            self.log.info(f"Enabling ARMv7 HAL catching")

            self.inject_monitor_stub()
            # self._end_of_stub_bkpt = self.target.set_breakpoint(self._stub_end)

            self.avatar.watchmen.add_watchman('BreakpointHit', AFTER, self._do_hal_return)

            self.log.info(f"Starting ARMv7 HAL catching thread")
            self.start()
        except:
            self.log.exception("Error starting ARMV7HALCallerProtocol")

    # TODO what this stub does
    MONITOR_STUB = ("" +
                    # Data
                    "func_addr:         .word 0x00000000\n" +

                    # Load and call the actual function
                    "ldr r4, =func_addr\n" +
                    "ldr r4, [r4]\n" +
                    "blx r4\n" +  # r0 holds return value now
                    "bkpt\n" +
                    "nop\n"
                    # Return to previous point of execution, leaves r12 modified
                    )

    def inject_monitor_stub(self, addr=0x20012000):
        """
        Injects a safe monitoring stub.
        This has the following effects:
        0. Pivot the VTOR to someplace sane
        1. Insert an infinite loop at addr
        2. Set the PC to addr
        3. set up logic for the injection of interrupt returns.
           Write to return_code_register to trigger an IRET
        4.
        :return:
        """
        self.log.warning(f"Injecting HAL caller stub into {self.target.name} at address 0x{addr:x}.")

        self._stub_base = addr
        self.log.info(f"_stub_base              = 0x{self._stub_base:08x}")
        self._stub_func_ptr = self._stub_base
        self.log.info(f"_stub_func_ptr          = 0x{self._stub_func_ptr:08x}")
        self._stub_entry = self._stub_base + 4
        self.log.info(f"_stub_entry             = 0x{self._stub_base:08x}")
        self._stub_end = self._stub_entry + 3 * 2
        self.log.info(f"_stub_end               = 0x{self._stub_end:08x}")

        # Inject the stub
        self.log.info(f"Injecting the stub ...")
        self.target.inject_asm(self.MONITOR_STUB, self._stub_base)

    def hal_call(self, function: HALFunction, return_address: int):
        self.command_queue.put((CMD_HAL_CALL, function, return_address))

    def _do_hal_return(self, avatar, message: BreakpointHitMessage, *args,
                       **kwargs):  # avatar, self, message: BreakpointHitMessage,
        self.log.debug(f"_do_hal_return got additional {args}, {kwargs}")
        if message.origin != self.target:
            return
        if message.address != self._stub_end:
            return
        current_func: HALFunction = self.current_hal_call[0]

        self.dispatch_message(HALExitMessage(self.target, current_func, return_val=self.target.regs.r0,
                                             return_address=self.current_hal_call[1]))
        self.current_hal_call = None

        self.target.regs.r0 = self.restore_regs_r0
        self.target.regs.r1 = self.restore_regs_r1
        self.target.regs.r2 = self.restore_regs_r2
        self.target.regs.r3 = self.restore_regs_r3
        self.target.regs.r4 = self.restore_regs_r4
        self.target.regs.sp = self.restore_regs_sp
        self.target.regs.lr = self.restore_regs_lr
        self.target.regs.pc = self.return_after_hal
        self.return_after_hal = None

    def _do_hal_call(self, function: HALFunction):
        assert self._stub_entry is not None, "Stub not injected yet"
        self.log.warning(f"_do_hal_call (func=0x{function.address:x}, args = {function.args})...")
        if self.target.state == TargetStates.RUNNING:
            self.target.stop()
        self.return_after_hal = self.target.regs.pc
        self.restore_regs_lr = self.target.regs.lr
        self.restore_regs_sp = self.target.regs.sp
        self.restore_regs_r0 = self.target.regs.r0
        self.restore_regs_r1 = self.target.regs.r1
        self.restore_regs_r2 = self.target.regs.r2
        self.restore_regs_r3 = self.target.regs.r3
        self.restore_regs_r4 = self.target.regs.r4
        self.target.write_memory(self._stub_func_ptr, size=4, value=function.address | 0x01)

        # TODO generic
        if len(function.args) >= 1:
            self.target.regs.r0 = function.args[0].value
        if len(function.args) >= 2:
            self.target.regs.r1 = function.args[1].value
        if len(function.args) >= 3:
            self.target.regs.r2 = function.args[2].value
        if len(function.args) >= 4:
            self.target.regs.r3 = function.args[3].value
        if len(function.args) >= 5:
            for i in range(4, len(function.args)):
                self.target.write_memory(self.target.regs.sp - 4 * (i - 4), size=4, value=function.args[i].value)
            self.target.regs.sp = self.target.regs.sp - 4 * (len(function.args) - 4)

        self.target.regs.pc = self._stub_entry
        self.target.cont()

    def continue_after_hal(self, message: HALExitMessage):
        self.command_queue.put((CMD_CONT,))

    def run(self):
        self.log.info("Starting ARMV7HALCallerProtocol thread")

        try:
            while not (self.avatar._close.is_set() or self._close.is_set()):
                try:
                    command = self.command_queue.get(timeout=1.0)
                    if command[0] == CMD_HAL_CALL:
                        function = command[1]
                        return_address = command[2]
                        assert self.current_hal_call is None, "Already in HAL call"

                        self.current_hal_call = (function, return_address)
                        self._do_hal_call(function)
                    elif command[0] == CMD_CONT:
                        self.target.cont()
                    else:
                        self.log.error(f"Unknown command {command[0]}")
                    self.command_queue.task_done()
                except queue.Empty:
                    continue

        except:
            self.log.exception("Error processing ARMV7HALCallerProtocol thread")
            self._closed.set()
        self.log.debug("ARMV7HALCallerProtocol thread exiting...")
        self._closed.set()

    def dispatch_message(self, message):
        self._avatar_fast_queue.put(message)

    def stop(self):
        """Stops the listening thread. Useful for teardown of the target"""
        self._close.set()
        self._closed.wait()
