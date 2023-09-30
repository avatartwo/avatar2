import queue
import sys
from enum import Enum
from threading import Thread, Event, Condition
import logging
import re
from time import sleep

from bitstring import BitStream, ReadError

from avatar2 import watch, OpenOCDTarget
from avatar2.archs.arm import ARM
from avatar2.targets import TargetStates
from avatar2.message import AvatarMessage, UpdateStateMessage, \
    BreakpointHitMessage, RemoteInterruptEnterMessage, TargetInterruptEnterMessage, TargetInterruptExitMessage
from avatar2.protocols.openocd import OpenOCDProtocol

# ARM System Control Block
SCB_CPUID = 0xe000ed00  # What is it
SCB_STIR = 0xe000ef00  # Send interrupts here
SCB_VTOR = 0xe000ed08  # Vector Table offset register

# NVIC stuff
NVIC_ISER0 = 0xe000e100

# ARMV7InterruptProtocol Constant Addresses
RCC_APB2ENR = 0x40021018
AFIO_MAPR = 0x40010004
DBGMCU_CR = 0xe0042004
COREDEBUG_DEMCR = 0xe000edfc
TPI_ACPR = 0xe0040010
TPI_SPPR = 0xe00400f0
TPI_FFCR = 0xe0040304
DWT_CTRL = 0xe0001000
ITM_LAR = 0xe0000fb0
ITM_TCR = 0xe0000e80
ITM_TER = 0xe0000e00
ETM_LAR = 0xe0041fb0
ETM_CR = 0xe0041000
ETM_TRACEIDR = 0xe0041200
ETM_TECR1 = 0xe0041024
ETM_FFRR = 0xe0041028
ETM_FFLR = 0xe004102c


class UniqueQueue(queue.Queue):
    def __contains__(self, item):
        with self.mutex:
            return item in self.queue

    def _init(self, maxsize):
        self.queue = list()

    def _put(self, item):
        if item not in self.queue:
            self.queue.append(item)

    def _get(self):
        return self.queue.pop(0)


class ARMV7INTForwarderProtocol(Thread):
    def __init__(self, avatar, target: OpenOCDTarget):
        self.avatar = avatar
        self._avatar_fast_queue = avatar.fast_queue
        self.target: OpenOCDTarget = target
        self._close = Event()
        self._closed = Event()

        self._monitor_stub_addr = None
        self._monitor_stub_base = None
        self._monitor_stub_isr = None
        self._monitor_stub_loop = None
        self._monitor_stub_ctrl = None
        self._original_vtor = None
        self.original_vt = None

        self.msg_counter = 0
        self._current_isr_num = 0

        self._internal_irq_queue = UniqueQueue()
        self._paused = Event()

        self.log = logging.getLogger(f'{avatar.log.name}.protocols.{self.__class__.__name__}')
        Thread.__init__(self, daemon=True, name=f"Thread-{self.__class__.__name__}")
        self.log.info(f"ARMV7InterruptProtocol initialized")

    def __del__(self):
        self.shutdown()

    def inject_interrupt(self, interrupt_number, cpu_number=0):
        self.log.critical(f"Injecting interrupt {interrupt_number}")
        # Set an interrupt using the STIR
        self.target.write_memory(SCB_STIR, 4, interrupt_number)

    def enable_interrupt(self, interrupt_number):
        """
        Enables an interrupt (e.g., in the NIVC)
        :param interrupt_number:
        :return:
        """
        self.log.critical(f"Enabling interrupt {interrupt_number}")
        assert (0 < interrupt_number < 256)
        iser_num = interrupt_number // 32  # 32 interrupts per ISER register
        iser_addr = NVIC_ISER0 + (iser_num * 4)  # Calculate ISER_X address
        iser_val = 1 << (interrupt_number % 32)  # Set the corresponding bit for the interrupt to 1
        self.target.write_memory(iser_addr, 4, iser_val)

    def get_enabled_interrupts(self, iser_num: int = 0):
        enabled_interrupts = self.target.read_memory(NVIC_ISER0 + iser_num * 4, size=4)
        return enabled_interrupts

    def set_enabled_interrupts(self, enabled_interrupts_bitfield: int, iser_num: int = 0):
        self.target.write_memory(NVIC_ISER0 + iser_num * 4, size=4, value=enabled_interrupts_bitfield)

    def get_vtor(self):
        return self.target.read_memory(SCB_VTOR, 4)

    def get_ivt_addr(self):
        if getattr(self.target, 'ivt_address', None) is not None:
            return self.target.ivt_address
        else:
            return self.get_vtor()

    def set_vtor(self, addr):
        self.log.warning(f"Changing VTOR location to 0x{addr:x}")
        res = self.target.write_memory(SCB_VTOR, 4, addr)
        if res:
            self.target.ivt_address = addr
        return res

    def get_isr(self, interrupt_num):
        return self.target.read_memory(
            self.get_ivt_addr() + (interrupt_num * 4), 4)

    def set_isr(self, interrupt_num, addr):
        base = self.get_ivt_addr()
        ivt_addr = base + (interrupt_num * 4)
        return self.target.write_memory(ivt_addr, 4, addr)

    def shutdown(self):
        if self.is_alive() is True:
            self.stop()

    def connect(self):
        if not isinstance(self.target.protocols.monitor, OpenOCDProtocol):
            raise Exception("ARMV7InterruptProtocol requires OpenOCDProtocol to be present.")

    def enable_interrupts(self):
        try:
            self.log.info(f"Enabling interrupts")
            if not isinstance(self.target.protocols.monitor, OpenOCDProtocol):
                raise Exception(
                    "ARMV7InterruptProtocol requires OpenOCDProtocol to be present.")

            self.inject_monitor_stub()

            self.log.info(f"Starting interrupt thread")
            self.start()
        except:
            self.log.exception("Error starting ARMV7InterruptProtocol")

    """
    What this does:
    Hang in a loop at `loop`
    When an interrupt comes, go to `stub`
    At `stub`, load `writeme`, if it's not zero, reset it, and jump to the written value.
    This lets us inject exc_return values into the running program
    """
    MONITOR_STUB = ("" +
                    "irq_buffer_ptr:    .word 0x00000000\n" +
                    "writeme:           .word 0x00000000\n" +

                    "init:\n" +  # Load the addresses for later access
                    "loop: b loop\n" +  # Wait for something to happen
                    "nop\n"

                    "stub:\n" +
                    "push {r4, r5}\n" +
                    # # "mrs  r0, IPSR\n" +  # Get the interrupt number
                    "nop\nnop\n" +  # Placeholder to be replaced with `mrs r5, IPSR` due to keystone error
                    "ldr  r1, =irq_buffer_ptr\n" +
                    "ldr  r2, =mtb_0\n" +
                    "ldr r3, [r1]\n" +  # Load the buffer pointer
                    "mov r4, r3\n" +
                    "add r4, r4, r2\n" +  # Calculate the address of the buffer pointer

                    # Ensure end of buffer flag is set
                    "adds r3, r3, #1\n" +  # Increment the buffer pointer
                    # NOTE: We need to use `movs` otherwise keystone will use `mov.w` which will crash a cortex m0+
                    "movs r5, #255\n" +  # For anding to implement wrap around
                    "ands r3, r3, r5\n" +  # Wrap around the buffer
                    "strb r3, [r1]\n" +  # Store updated buffer pointer
                    "strb r5, [r2, r3]\n" +  # Set the end of buffer flag
                    "strb r0, [r4]\n" +  # Save the interrupt number

                    "intloop:\n" +  # Hang in a loop until `writeme` is not 0
                    "ldr r3, =writeme\n" +
                    "ldr r4, [r3]\n" +
                    "cmp r4, #0\n" +
                    "beq intloop\n"

                    "movs r4, #0\n" +
                    "str  r4, [r3]\n" +  # Reset `writeme`
                    "pop {r4, r5}\n" +

                    "bx   lr\n"  # Return from the interrupt, set by the interrupt calling convention
                    )

    def _get_stub(self, mtb_size=256):
        mtb_declaration = [f"mtb_{i}: .hword 0x0000" for i in range(mtb_size)]
        mtb_declaration[0] = "mtb_0: .hword 0x00ff"
        mtb_declaration = "\n".join(mtb_declaration)
        return mtb_declaration + self.MONITOR_STUB

    def inject_monitor_stub(self, addr=0x20010000, vtor=0x20011000, num_isr=48):
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
        self.log.warning(
            f"Injecting monitor stub into {self.target.name}. (IVT: 0x{self.get_ivt_addr():08x}, 0x{self.get_vtor():08x}, 0x{vtor:08x})")
        MTB_SIZE = 256

        self._monitor_stub_addr = addr
        self.log.info(f"_monitor_stub_addr     = 0x{self._monitor_stub_addr:08x}")
        self._monitor_stub_base = self._monitor_stub_addr + MTB_SIZE * 2
        self.log.info(f"_monitor_stub_base     = 0x{self._monitor_stub_base:08x}")
        self._monitor_stub_loop = self._monitor_stub_base + 4 * 2
        self.log.info(f"_monitor_stub_loop     = 0x{self._monitor_stub_loop:08x}")
        self._monitor_stub_isr = self._monitor_stub_loop + 4
        self.log.info(f"_monitor_stub_isr      = 0x{self._monitor_stub_isr:08x}")
        self._monitor_stub_ctrl = self._monitor_stub_base + 4
        self.log.info(f"_monitor_stub_writeme  = 0x{self._monitor_stub_ctrl:08x}")

        # Pivot VTOR, if needed
        # On CM0, you can't, so don't.
        self._original_vtor = self.get_vtor()
        assert self._original_vtor != vtor, "VTOR is already set to the desired value."

        self.set_vtor(vtor)
        self.log.info(f"Validate new VTOR address 0x{self.get_vtor():8x}")

        # Sometimes, we need to gain access to the IVT (make it writable). Do that here.
        if getattr(self.target, 'ivt_unlock', None) is not None:
            unlock_addr, unlock_val = self.target.ivt_unlock
            self.target.write_memory(unlock_addr, 4, unlock_val)

        self.log.info(f"Inserting the stub ...")
        # Inject the stub
        isr_offset = self._monitor_stub_isr - self._monitor_stub_addr + 2  # +2 for push instruction
        self.target.inject_asm(self._get_stub(MTB_SIZE), self._monitor_stub_addr,
                               patch={isr_offset: b'\xef\xf3\x05\x80'})

        self.log.info(f"Setting up IVT...")
        self.original_vt = self.target.read_memory(self._original_vtor, size=4, num_words=num_isr)
        # Set the IVT to our stub but DON'T wipe out the 0'th position.
        self.target.write_memory(vtor, value=self.target.read_memory(self._original_vtor, size=4), size=4)
        for interrupt_num in range(1, num_isr):
            self.set_isr(interrupt_num, self._monitor_stub_isr + 1)  # +1 for thumb mode

        if self.target.state != TargetStates.STOPPED:
            self.log.critical(
                "Not setting PC to the monitor stub; Target not stopped")
        else:
            self.target.write_register('pc', self._monitor_stub_loop)
            self.log.warning(f"Updated PC to 0x{self.target.regs.pc:8x}")

    def inject_exc_return(self):
        if not self._monitor_stub_base:
            self.log.error(
                "You need to inject the monitor stub before you can inject exc_returns")
            return False
        int_num = self._current_isr_num
        self._current_isr_num = None
        self.log.info(f"Returning from interrupt {int_num}.")
        # We can just BX LR for now.
        return self.target.write_memory(address=self._monitor_stub_ctrl, size=4, value=1)

    def queue_irq(self, interrupt_num, isr_addr):
        self._internal_irq_queue.put((interrupt_num, isr_addr))

    def pause(self):
        self._paused.set()
        self.log.warning("IRQ protocol paused")

    def resume(self):
        self.log.warning("IRQ protocol resuming...")
        self._paused.clear()

    def _dispatch_exception_packet(self, int_num):
        self._current_isr_num = int_num

        self.log.debug(f"Dispatching exception for interrupt number {int_num}")

        msg = TargetInterruptEnterMessage(self.target, self.msg_counter, interrupt_num=int_num,
                                          isr_addr=self.original_vt[int_num])
        self.msg_counter += 1
        self._avatar_fast_queue.put(msg)

    def _panic_exec(self):
        self.log.critical(f"Received hard-fault exception, stopping target")
        if self.target.state == TargetStates.RUNNING:
            self.target.stop()
        self._close.set()

    def run(self):
        TICK_DELAY = 0.0001
        self.log.info("Starting ARMV7InterruptProtocol thread")

        # Wait for init
        while self._monitor_stub_addr is None:
            sleep(TICK_DELAY)

        mtb_pos = 0
        try:
            while not (self.avatar._close.is_set() or self._close.is_set()):
                try:
                    if not self._paused.is_set() and self._internal_irq_queue.qsize() != 0:
                        irq_num, _ = self._internal_irq_queue.get_nowait()
                        self.log.info(f"IRQ event from queue {irq_num} q={self._internal_irq_queue}")
                        self._dispatch_exception_packet(int_num=irq_num)
                        self._internal_irq_queue.task_done()
                        if irq_num == 0x3:  # Hard-fault
                            self._panic_exec()
                        sleep(TICK_DELAY)
                        continue
                except queue.Empty:
                    pass

                mtb_val = self.target.read_memory(self._monitor_stub_addr + mtb_pos, size=1)
                if mtb_val == 0xff:
                    sleep(TICK_DELAY)
                    continue

                mtb_pos = (mtb_pos + 1) & 0xff

                self.log.info(f"IRQ event {mtb_val}")
                if self._paused.is_set():
                    self.queue_irq(mtb_val, self.original_vt[mtb_val])
                    self.inject_exc_return()  # TODO: This has a lot of side effects
                else:
                    self._dispatch_exception_packet(int_num=mtb_val)
                if mtb_val == 0x3:  # Hard-fault
                    self._panic_exec()
        except:
            self.log.exception("Error processing trace")
        self.log.info("Interrupt thread exiting...")
        self._closed.set()

    def stop(self):
        """Stops the listening thread. Useful for teardown of the target"""
        self._close.set()
        self._closed.wait()
