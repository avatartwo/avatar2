import sys
from enum import Enum
from threading import Thread, Event, Condition
import logging
import re
from time import sleep

from bitstring import BitStream, ReadError

from avatar2 import watch
from avatar2.archs.arm import ARM
from avatar2.targets import TargetStates
from avatar2.message import AvatarMessage, UpdateStateMessage, \
    BreakpointHitMessage, RemoteInterruptEnterMessage, InterruptEnterMessage
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


class HWInterruptState(Enum):
    HW_INTERRUPT_STATE_UNDEF = 0x000000ff
    HW_INTERRUPT_STATE_IDLE = 0
    HW_INTERRUPT_STATE_INT = 1

    @classmethod
    def has_value(cls, value):
        return value in cls._value2member_map_


class ARMV7InterruptRecordingProtocol(Thread):
    def __init__(self, avatar, origin):
        self._original_vtor = None
        self.avatar = avatar
        self._avatar_queue = avatar.queue
        self._avatar_fast_queue = avatar.fast_queue
        self._origin = origin
        self._close = Event()
        self._closed = Event()
        self._monitor_stub_base = None
        self._monitor_stub_isr = None
        self._monitor_stub_vt_buffer = None
        self._monitor_stub_trace_buffer = None
        self._monitor_stub_start = None
        self.log = logging.getLogger(f'{avatar.log.name}.protocols.armv7-interrupt-recording')
        Thread.__init__(self, daemon=True)
        self.log.info(f"ARMV7InterruptRecordingProtocol initialized")

    def __del__(self):
        self.shutdown()

    def get_vtor(self):
        return self._origin.read_memory(SCB_VTOR, 4)

    def get_ivt_addr(self):
        if getattr(self._origin, 'ivt_address', None) is not None:
            return self._origin.ivt_address
        else:
            return self.get_vtor()

    def set_vtor(self, addr):
        self.log.warning(f"Changing VTOR location to 0x{addr:x}")
        res = self._origin.write_memory(SCB_VTOR, 4, addr)
        if res:
            self._origin.ivt_address = addr
        return res

    def shutdown(self):
        if self.is_alive() is True:
            self.stop()

    def connect(self):
        if not isinstance(self._origin.protocols.monitor, OpenOCDProtocol):
            raise Exception("ARMV7InterruptRecordingProtocol requires OpenOCDProtocol to be present.")

    def enable_interrupt_recording(self):
        try:
            self.log.info(f"Enabling interrupt recording")
            if not isinstance(self._origin.protocols.monitor, OpenOCDProtocol):
                raise Exception(
                    "ARMV7InterruptRecordingProtocol requires OpenOCDProtocol to be present.")

            self.inject_monitor_stub()

            self.log.info(f"Starting interrupt thread")
            self.start()
        except:
            self.log.exception("Error starting ARMV7InterruptRecordingProtocol")

    # TODO what this stub does
    MONITOR_STUB = ("" +
                    "outstat: .word 0xdeafbeef\n" +

                    "init:  \n" +  # Load the addresses for later access
                    "ldr  r0, =outstat\n" +
                    "ldr  r2, =irq_buffer_0\n" +
                    "ldr  r3, =vt_buffer_0\n" +
                    "movs r4, #0\n" +  # Signal Avatar that the stub initialized
                    "strb  r4, [r0]\n" +
                    "movs r7, #255\n" +  # Ensure end of buffer flag is set
                    "strb  r7, [r2]\n" +
                    "movs r4, #0\n" +
                    "movs r0, #127\n" +  # For anding to implement wrap around
                    "movs r1, #128\n" +  # For oring to flip 8th bit

                    "loop: b loop\n" +  # Wait for something to happen
                    "nop\n" +

                    "stub: \n" +
                    # "mrs  r5, IPSR\n" +  # Get the interrupt number
                    "nop\nnop\n" +  # Placeholder to be replaced with `mrs r5, IPSR` due to keystone error
                    "strb  r5, [r2, r4]\n" +  # Save the interrupt number
                    "adds r4, r4, #1\n" +  # Increment the buffer pointer
                    "ands r4, r4, r0\n" +  # Wrap around the buffer
                    # Ensure end of buffer flag is set
                    "movs r7, #255\n" +
                    "strb r7, [r2, r4]\n" +

                    # Setup jump to interrupt handler
                    "mov r6, r5\n" +
                    "lsls r6, #2\n" +  # Calculate interrupt offset
                    "adds r6, r6, r3\n" +
                    "ldr  r6, [r6]\n" +  # Load the interrupt handler address

                    # Call the interrupt handler
                    "mov r7, lr\n" +
                    "push {r0, r1, r2, r3, r4, r5, r7}\n"
                    "blx r6\n" +  # Jump to interrupt handler
                    "pop {r0, r1, r2, r3, r4, r5, r7}\n"
                    "mov lr, r7\n" +

                    # Store the interrupt return
                    "orrs r5, r5, r1\n" +  # Flip 8th bit
                    "strb  r5, [r2, r4]\n" +  # Save the interrupt number with exit flag (highest bit)
                    "adds r4, r4, #1\n" +  # Increment the buffer pointer
                    "ands r4, r4, r0\n" +  # Wrap around the buffer
                    # Ensure end of buffer flag is set
                    "movs r7, #255\n" +
                    "strb  r7, [r2, r4]\n" +

                    "bx lr\n"  # Return from the interrupt, set by the interrupt calling convention
                    )

    def _get_stub(self, vt_size=48, irq_buffer_size=256):
        vt_declaration = [f"vt_buffer_{i}: .word 0x00000000" for i in range(vt_size)]
        vt_declaration = "\n".join(vt_declaration)
        buffer_declaration = [f"irq_buffer_{i}: .hword 0x0000" for i in range(irq_buffer_size)]
        buffer_declaration = "".join(buffer_declaration)
        return vt_declaration + buffer_declaration + self.MONITOR_STUB

    def set_isr(self, interrupt_num, addr):
        base = self.get_ivt_addr()
        ivt_addr = base + (interrupt_num * 4)
        return self._origin.write_memory(ivt_addr, 4, addr)

    def inject_monitor_stub(self, addr=0x20001234, vtor=0x20002000, num_isr=48):
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
            f"Injecting monitor stub into {self._origin.name}. (IVT: 0x{self.get_ivt_addr():08x}, 0x{self.get_vtor():08x}, 0x{vtor:08x})")

        self._monitor_stub_base = addr
        self.log.info(f"_monitor_stub_base          = 0x{self._monitor_stub_base:08x}")
        self._monitor_stub_trace_buffer = addr + num_isr * 4
        self.log.info(f"_monitor_stub_trace_buffer  = 0x{self._monitor_stub_trace_buffer:08x}")
        self._monitor_stub_vt_buffer = addr
        self.log.info(f"_monitor_stub_vt_buffer     = 0x{self._monitor_stub_vt_buffer:08x}")
        self._monitor_stub_start = addr + num_isr * 4 + 256 * 2 + 4
        self.log.info(f"_monitor_stub_start         = 0x{self._monitor_stub_start:08x}")
        self._monitor_stub_isr = self._monitor_stub_start + 24
        self.log.info(f"_monitor_stub_isr           = 0x{self._monitor_stub_isr:08x}")

        # Pivot VTOR, if needed
        # On CM0, you can't, so don't.
        self._original_vtor = self.get_vtor()
        assert self._original_vtor != vtor, "VTOR is already set to the desired value."

        self.set_vtor(vtor)
        self.log.info(f"Validate new VTOR address 0x{self.get_vtor():8x}")

        # Sometimes, we need to gain access to the IVT (make it writable). Do that here.
        if getattr(self._origin, 'ivt_unlock', None) is not None:
            unlock_addr, unlock_val = self._origin.ivt_unlock
            self._origin.write_memory(unlock_addr, 4, unlock_val)

        self.log.info(f"Inserting the stub ...")
        # Inject the stub
        stub_offset = self._monitor_stub_isr - self._monitor_stub_base
        self._origin.inject_asm(self._get_stub(), self._monitor_stub_base, patch={stub_offset: b'\xef\xf3\x05\x85'})

        self.log.info(f"Setting up IVT buffer...")
        # Copy the vector table to our buffer
        original_vt = self._origin.read_memory(self._original_vtor, size=4, num_words=num_isr)
        self._origin.write_memory(self._monitor_stub_vt_buffer, value=original_vt, size=4, num_words=num_isr)

        self.log.info(f"Setting up IVT...")
        # Set the IVT to our stub but DON'T wipe out the 0'th position.
        self._origin.write_memory(vtor, value=self._origin.read_memory(self._original_vtor, size=4), size=4)
        for interrupt_num in range(1, num_isr):
            self.set_isr(interrupt_num, self._monitor_stub_isr + 1)  # +1 for thumb mode

        if self._origin.state != TargetStates.STOPPED:
            self.log.warning(
                "Not setting PC to the monitor stub; Target not stopped")
        else:
            self._origin.regs.pc = self._monitor_stub_start
            self.log.warning(f"Setting PC to 0x{self._origin.regs.pc:8x}")

    def dispatch_exception_packet(self):
        # To read the xPSR register containing the ISR number we need to halt the target.
        self._origin.stop()
        int_num = self.get_current_isr_num()
        self._origin.cont()

        self.log.warning(f"Dispatching exception for interrupt number {int_num}")

        msg = InterruptEnterMessage(self._origin, int_num)
        self._avatar_fast_queue.put(msg)

    def run(self):
        TICK_DELAY = 0.0001
        self.log.warning("Starting ARMV7InterruptRecordingProtocol thread")
        buffer_pos = 0
        init = False
        try:
            while not (self.avatar._close.is_set() or self._close.is_set()):
                if self._monitor_stub_base is None:
                    sleep(TICK_DELAY)
                    continue
                if not init:
                    curr_isr = self._origin.read_memory(address=self._monitor_stub_trace_buffer + buffer_pos, size=1)
                    if curr_isr == 255:
                        init = True
                        self.log.warning("Starting ARMV7InterruptRecordingProtocol initialization complete")
                    else:
                        sleep(TICK_DELAY)
                        continue

                # curr_isr = self._origin.read_memory(address=self._monitor_stub_trace_buffer + buffer_pos, size=1)
                # while curr_isr != 255:
                #     if curr_isr > 0x80:
                #         self.log.warning(f"ISR-Exit {curr_isr & 0x7f} triggered")
                #     else:
                #         self.log.warning(f"ISR-Enter {curr_isr} triggered")
                #     buffer_pos = (buffer_pos + 1) & 0xff
                #     curr_isr = self._origin.read_memory(address=self._monitor_stub_trace_buffer + buffer_pos, size=1)

                sleep(TICK_DELAY)
        except:
            self.log.exception("Error processing trace")
            self._closed.set()
        self.log.debug("Interrupt thread exiting...")
        self._closed.set()

    def stop(self):
        """Stops the listening thread. Useful for teardown of the target"""
        self._close.set()
        self._closed.wait()
