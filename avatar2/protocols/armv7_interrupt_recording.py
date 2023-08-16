from enum import Enum
from threading import Thread, Event
import logging
from time import sleep

from avatar2.targets import TargetStates
from avatar2.message import TargetInterruptEnterMessage, TargetInterruptExitMessage
from avatar2.protocols.openocd import OpenOCDProtocol

# ARM System Control Block
SCB_VTOR = 0xe000ed08  # Vector Table offset register
# NVIC stuff
NVIC_ISER0 = 0xe000e100


class ARMV7InterruptRecordingProtocol(Thread):
    def __init__(self, avatar, origin):
        self._original_vtor = None
        self.avatar = avatar
        self._avatar_fast_queue = avatar.fast_queue
        self._origin = origin
        self._close = Event()
        self._closed = Event()
        self._monitor_stub_base = None
        self._monitor_stub_isr = None
        self._monitor_stub_vt_buffer = None
        self._monitor_stub_trace_buffer = None
        self._monitor_stub_mtb = None
        self.msg_counter = 0
        self.original_vt = None
        self.log = logging.getLogger(f'{avatar.log.name}.protocols.{self.__class__.__name__}')
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

    def get_enabled_interrupts(self, iser_num: int = 0):
        enabled_interrupts = self._origin.read_memory(NVIC_ISER0 + iser_num * 4, size=4)
        return enabled_interrupts

    # TODO what this stub does
    MONITOR_STUB = ("" +
                    # Data
                    # vt_buffer_X: .word 0x00000000 # Buffer holding the original vector table
                    # irq_buffer_X: .hword 0x0000 # MTB ring buffer of interrupt events
                    "irq_buffer_ptr: .word 0xdeafbeef\n" +

                    # "stub: \n" +
                    "push {r4, r5, r6, r7}\n" +
                    # # "mrs  r0, IPSR\n" +  # Get the interrupt number
                    "nop\nnop\n" +  # Placeholder to be replaced with `mrs r5, IPSR` due to keystone error
                    "ldr r1, =irq_buffer_ptr\n" +
                    "ldr r2, =irq_buffer_0\n" +
                    "ldr r3, [r1]\n" +  # Load the buffer pointer
                    "mov r4, r3\n" +
                    "add r4, r4, r2\n" +

                    # Ensure end of buffer flag is set
                    "adds r3, r3, #1\n" +  # Increment the buffer pointer
                    "movs r5, #255\n" +  # For anding to implement wrap around
                    "ands r3, r3, r5\n" +  # Wrap around the buffer
                    "strb r5, [r2, r3]\n" +

                    # Save the interrupt number
                    "strb r0, [r4]\n" +

                    # Setup jump to interrupt handler
                    "ldr r2, =vt_buffer_0\n" +
                    "mov r6, r0\n" +
                    "lsls r6, #2\n" +  # Calculate interrupt offset
                    "adds r6, r6, r2\n" +
                    "ldr  r6, [r6]\n" +  # Load the interrupt handler address

                    # Call the interrupt handler
                    "mov r7, lr\n" +
                    "push {r0, r1, r2, r3, r4, r5, r6, r7}\n"
                    "blx r6\n" +  # Jump to interrupt handler
                    "pop {r0, r1, r2, r3, r4, r5, r6, r7}\n"
                    "mov lr, r7\n" +

                    # Store the interrupt return
                    "ldr r2, =irq_buffer_0\n" +
                    "mov r4, r3\n" +
                    "add r4, r4, r2\n" +

                    # Ensure end of buffer flag is set
                    "adds r3, r3, #1\n" +  # Increment the buffer pointer
                    "movs r5, #255\n" +  # For anding to implement wrap around
                    "ands r3, r3, r5\n" +  # Wrap around the buffer
                    "strb r3, [r1]\n" +  # Save the buffer pointer
                    "strb  r5, [r2, r3]\n" +

                    "movs r5, #128\n" +  # For oring to signal interrupt exit
                    "orrs r5, r5, r0\n" +  # Flip 8th bit
                    "strb  r5, [r4]\n" +  # Save the interrupt number with exit flag (highest bit)

                    # Restore registers and return
                    "pop {r4, r5, r6, r7}\n" +
                    "bx lr\n"  # Return from the interrupt, set by the interrupt calling convention
                    )

    def _get_stub(self, vt_size=48, irq_buffer_size=256):
        vt_declaration = [f"vt_buffer_{i}: .word 0x00000000" for i in range(vt_size)]
        vt_declaration = "\n".join(vt_declaration)
        buffer_declaration = [f"irq_buffer_{i}: .hword 0x0000" for i in range(irq_buffer_size)]
        buffer_declaration = "\n".join(buffer_declaration)
        return vt_declaration + buffer_declaration + self.MONITOR_STUB

    def set_isr(self, interrupt_num, addr):
        base = self.get_ivt_addr()
        ivt_addr = base + (interrupt_num * 4)
        return self._origin.write_memory(ivt_addr, 4, addr)

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
            f"Injecting monitor stub into {self._origin.name}. (IVT: 0x{self.get_ivt_addr():08x}, 0x{self.get_vtor():08x}, 0x{vtor:08x})")

        self._monitor_stub_base = addr
        self.log.info(f"_monitor_stub_base          = 0x{self._monitor_stub_base:08x}")
        self._monitor_stub_trace_buffer = addr + num_isr * 4
        self.log.info(f"_monitor_stub_trace_buffer  = 0x{self._monitor_stub_trace_buffer:08x}")
        self._monitor_stub_vt_buffer = addr
        self.log.info(f"_monitor_stub_vt_buffer     = 0x{self._monitor_stub_vt_buffer:08x}")
        self._monitor_stub_mtb = addr + num_isr * 4
        self.log.info(f"_monitor_stub_mtb           = 0x{self._monitor_stub_mtb:08x}")
        self._monitor_stub_isr = addr + num_isr * 4 + 256 * 2 + 4
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
        stub_offset = self._monitor_stub_isr - self._monitor_stub_base + 2
        self._origin.inject_asm(self._get_stub(), self._monitor_stub_base, patch={stub_offset: b'\xef\xf3\x05\x80'})
        self._origin.write_memory(self._monitor_stub_isr - 4, size=4, value=0x00)  # set irq_buffer_ptr to 0
        self._origin.write_memory(self._monitor_stub_mtb, size=1, value=0xff)  # Ensure end of buffer flag

        self.log.info(f"Setting up IVT buffer...")
        # Copy the vector table to our buffer
        self.original_vt = self._origin.read_memory(self._original_vtor, size=4, num_words=num_isr)
        self._origin.write_memory(self._monitor_stub_vt_buffer, value=self.original_vt, size=4, num_words=num_isr)

        self.log.info(f"Setting up IVT...")
        # Set the IVT to our stub but DON'T wipe out the 0'th position.
        self._origin.write_memory(vtor, value=self._origin.read_memory(self._original_vtor, size=4), size=4)
        for interrupt_num in range(1, num_isr):
            self.set_isr(interrupt_num, self._monitor_stub_isr + 1)  # +1 for thumb mode

    def dispatch_message(self, message):
        self._avatar_fast_queue.put(message)

    def run(self):
        TICK_DELAY = 0.0001
        self.log.info("Starting ARMV7InterruptRecordingProtocol thread")

        # Wait for init
        while self._monitor_stub_base is None:
            sleep(TICK_DELAY)

        buffer_pos = 0
        try:
            while not (self.avatar._close.is_set() or self._close.is_set()):
                curr_isr = self._origin.read_memory(address=self._monitor_stub_trace_buffer + buffer_pos, size=1)
                if curr_isr == 0xff:
                    sleep(TICK_DELAY)
                    continue

                self.msg_counter += 1
                buffer_pos = (buffer_pos + 1) & 0xff

                if curr_isr > 0x80:
                    curr_isr = curr_isr & 0x7f
                    addr = self.original_vt[curr_isr]
                    self.dispatch_message(
                        TargetInterruptExitMessage(self._origin, self.msg_counter, interrupt_num=curr_isr,
                                                   isr_addr=addr))
                else:
                    addr = self.original_vt[curr_isr]
                    self.dispatch_message(
                        TargetInterruptEnterMessage(self._origin, self.msg_counter, interrupt_num=curr_isr,
                                                    isr_addr=addr))


        except:
            self.log.exception("Error processing trace")
            self._closed.set()
        self.log.debug("Interrupt thread exiting...")
        self._closed.set()

    def stop(self):
        """Stops the listening thread. Useful for teardown of the target"""
        self._close.set()
        self._closed.wait()
