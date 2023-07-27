import queue
from enum import Enum
from threading import Thread, Event
import logging
from time import sleep
from types import MethodType

from avatar2.targets import TargetStates
from avatar2.message import TargetInterruptEnterMessage, TargetInterruptExitMessage, BreakpointHitMessage, \
    HALExitMessage
from avatar2.protocols.openocd import OpenOCDProtocol
from avatar2.watchmen import AFTER


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
        self._stub_return_ptr = None
        self._stub_arg_init_offset = None
        self._stub_args = None
        self._stub_entry = None
        self._stub_end = None

        self.current_hal_call = None

        self.log = logging.getLogger(f'{avatar.log.name}.protocols.{self.__class__.__name__}')
        Thread.__init__(self, daemon=True)
        self.log.info(f"ARMV7HALCallerProtocol initialized")

    def __del__(self):
        self.shutdown()

    def shutdown(self):
        if self.is_alive() is True:
            self.stop()

    def connect(self):
        pass

    def enable(self):
        try:
            self.log.info(f"Enabling ARMv7 HAL catching")

            self.inject_monitor_stub()
            self._end_of_stub_bkpt = self.target.set_breakpoint(self._stub_end - 4)

            self.avatar.watchmen.add_watchman('BreakpointHit', AFTER, self._handle_breakpoint)

            self.log.info(f"Starting ARMv7 HAL catching thread")
            self.start()
        except:
            self.log.exception("Error starting ARMV7HALCallerProtocol")

    # TODO what this stub does
    MONITOR_STUB = ("" +
                    # Data
                    "func_addr:         .word 0x00000000\n" +
                    "return_addr:       .word 0x00000000\n" +
                    "arg_init_offset:   .word 0x00000000\n" +
                    # Arguments
                    "arg_0: .word 0x00000000\n" +  # 0
                    "arg_1: .word 0x00000000\n" +  # 4
                    "arg_2: .word 0x00000000\n" +  # 8
                    "arg_3: .word 0x00000000\n" +  # 12
                    "arg_4: .word 0x00000000\n" +  # 16
                    "arg_5: .word 0x00000000\n" +  # 20
                    "arg_6: .word 0x00000000\n" +  # 24
                    "arg_7: .word 0x00000000\n" +  # 28

                    "push {r0, r1, r2, r3, r4}\n" +
                    "ldr r0, =arg_init_offset\n" +
                    "ldr r4, =func_addr\n" +
                    "mov r3, pc\n" +
                    "ldr r1, [r3, #44]\n" +
                    "ldr r0, [r0]\n" +
                    "add pc, pc, r0\n" +  # Jump to correct argument setup for the number of arguments
                    # Argument setup for registers and stack, up to 8 arguments
                    "ldr r0, [r1, #28]\n" +
                    "push {r0}\n" +
                    "ldr r0, [r1, #24]\n" +
                    "push {r0}\n" +
                    "ldr r0, [r1, #20]\n" +
                    "push {r0}\n" +
                    "ldr r0, [r1, #16]\n" +
                    "push {r0}\n" +
                    "ldr r3, [r1, #12]\n" +
                    "ldr r2, [r1, #8]\n" +
                    "ldr r1, [r1, #4]\n" +
                    "ldr r0, =arg_0\n" +
                    "ldr r0, [r0, #0]\n" +
                    # Load and call the actual function
                    "ldr r4, [r4, #0]\n" +
                    "blx r4\n" +  # r0 hold return value now
                    # Return to previous point of execution, leaves r12 modified
                    "ldr r1, =return_addr\n" +
                    "ldr r1, [r1]\n" +
                    "mov r12, r1\n" +
                    "pop {r0, r1, r2, r3, r4}\n" +
                    "bx r12\n"  # Return from the interrupt, set by the interrupt calling convention
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
        self._stub_return_ptr = self._stub_base + 4
        self.log.info(f"_stub_return_ptr        = 0x{self._stub_return_ptr:08x}")
        self._stub_arg_init_offset = self._stub_base + 8
        self.log.info(f"_stub_arg_init_offset   = 0x{self._stub_arg_init_offset:08x}")
        self._stub_args = self._stub_base + 12
        self.log.info(f"_stub_args              = 0x{self._stub_args:08x}")
        self._stub_entry = self._stub_args + 8 * 4
        self.log.info(f"_stub_entry             = 0x{self._stub_base:08x}")
        self._stub_end = self._stub_entry + 32 * 2
        self.log.info(f"_stub_end               = 0x{self._stub_end:08x}")

        # Inject the stub
        self.log.info(f"Injecting the stub ...")
        self.target.inject_asm(self.MONITOR_STUB, self._stub_base)

    def hal_call(self, func_ptr, args, return_address):
        self.command_queue.put((func_ptr, args, return_address))

    def _handle_breakpoint(self, avatar, message: BreakpointHitMessage, *args,
                           **kwargs):  # avatar, self, message: BreakpointHitMessage,
        self.log.debug(f"_handle_breakpoint got additional {args}, {kwargs}")
        if message.origin != self.target:
            return
        if message.address != self._end_of_stub_bkpt:
            return
        self.dispatch_message(HALExitMessage(self.target, self.current_hal_call[0], return_val=self.target.regs.r0,
                                             return_address=self.current_hal_call[1]))
        self.current_hal_call = None

    def _do_hal_call(self, func_ptr, args):
        assert self._stub_entry is not None, "Stub not injected yet"
        self.log.warning(f"_do_hal_call (func=0x{func_ptr:x}, args = {args})...")
        self.target.stop()
        old_pc = self.target.regs.pc
        arg_setup_offset = -2  # Compensation for increment due to add anyways
        if len(args) > 4:
            arg_setup_offset += (8 - len(args)) * 4
        else:
            arg_setup_offset += 16 + (4 - len(args)) * 2
        self.target.write_memory(self._stub_func_ptr + 1, size=4, value=func_ptr)
        self.target.write_memory(self._stub_return_ptr, size=4, value=old_pc)
        self.target.write_memory(self._stub_arg_init_offset, size=4, value=arg_setup_offset)
        for i, arg in enumerate(args):
            self.target.write_memory(self._stub_args + i * 4, size=4, value=arg.value)

        self.target.regs.pc = self._stub_entry
        self.target.cont()

    def run(self):
        self.log.info("Starting ARMV7HALCallerProtocol thread")

        try:
            while not (self.avatar._close.is_set() or self._close.is_set()):
                try:
                    func_ptr, args, return_address = self.command_queue.get(timeout=1.0)
                    assert self.current_hal_call is None, "Already in HAL call"

                    self.current_hal_call = (func_ptr, return_address)
                    self._do_hal_call(func_ptr, args)
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
