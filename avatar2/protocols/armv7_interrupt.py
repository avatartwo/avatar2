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
    BreakpointHitMessage, RemoteInterruptEnterMessage, TargetInterruptEnterMessage
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


class ARMV7InterruptProtocol(Thread):
    def __init__(self, avatar, origin):
        self.avatar = avatar
        self._avatar_queue = avatar.queue
        self._avatar_fast_queue = avatar.fast_queue
        self._origin = origin
        self._close = Event()
        self._closed = Event()
        self._monitor_stub_base = None
        self._monitor_stub_isr = None
        self._monitor_stub_init = None
        self._monitor_stub_writeme = None
        self._monitor_stub_state = None
        self.original_vt = None
        self.msg_counter = 0
        self.log = logging.getLogger(f'{avatar.log.name}.protocols.armv7-interrupt')
        Thread.__init__(self, daemon=True)
        self.log.info(f"ARMV7InterruptProtocol initialized")

    def __del__(self):
        self.shutdown()

    def inject_interrupt(self, interrupt_number, cpu_number=0):
        # Set an interrupt using the STIR
        self._origin.write_memory(SCB_STIR, 4, interrupt_number)

    def enable_interrupt(self, interrupt_number):
        """
        Enables an interrupt (e.g., in the NIVC)
        :param interrupt_number:
        :return:
        """
        assert (0 < interrupt_number < 256)
        iser_num = interrupt_number // 32  # 32 interrupts per ISER register
        iser_addr = NVIC_ISER0 + (iser_num * 4)  # Calculate ISER_X address
        iser_val = 1 << (interrupt_number % 32)  # Set the corresponding bit for the interrupt to 1
        self._origin.write_memory(iser_addr, 4, iser_val)

    def get_enabled_interrupts(self, iser_num: int = 0):
        enabled_interrupts = self._origin.read_memory(NVIC_ISER0 + iser_num * 4, size=4)
        return enabled_interrupts

    def set_enabled_interrupts(self, enabled_interrupts_bitfield: int, iser_num: int = 0):
        self._origin.write_memory(NVIC_ISER0 + iser_num * 4, size=4, value=enabled_interrupts_bitfield)

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

    def get_isr(self, interrupt_num):
        return self._origin.read_memory(
            self.get_ivt_addr() + (interrupt_num * 4), 4)

    def set_isr(self, interrupt_num, addr):
        base = self.get_ivt_addr()
        ivt_addr = base + (interrupt_num * 4)
        return self._origin.write_memory(ivt_addr, 4, addr)

    def shutdown(self):
        if self.is_alive() is True:
            self.stop()

    def connect(self):
        if not isinstance(self._origin.protocols.monitor, OpenOCDProtocol):
            raise Exception("ARMV7InterruptProtocol requires OpenOCDProtocol to be present.")

    def enable_interrupts(self):
        try:
            self.log.info(f"Enabling interrupts")
            if not isinstance(self._origin.protocols.monitor, OpenOCDProtocol):
                raise Exception(
                    "ARMV7InterruptProtocol requires OpenOCDProtocol to be present.")
            # self.log.debug("Resetting target")
            # self._origin.protocols.monitor.reset()

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
                    "dcscr:   .word 0xDEADBEEF\n" +
                    "outstat: .word 0x000000ff\n" +
                    "writeme: .word 0x00000000\n" +

                    "init:\n" +  # Load the addresses for later access
                    "ldr  r1, =dcscr\n" +
                    "ldr  r2, =outstat\n" +
                    "ldr  r3, =writeme\n" +
                    # NOTE: We need to use `movs` otherwise keystone will use `mov.w` which will crash a cortex m0+
                    "movs r4, #0\n" +  # Signal Avatar that the stub initialized
                    "str  r4, [r2]\n"

                    "loop: b loop\n" +  # Wait for something to happen
                    "nop\n"

                    "stub:\n" +
                    "movs r4, #1\n" +  # Signal Avatar that there has been an interrupt
                    "str  r4, [r2]\n"

                    "intloop:\n" +  # Hang in a loop until `writeme` is not 0
                    "ldr r4, [r3]\n" +
                    "cmp r4, #0\n" +
                    "beq intloop\n"

                    "movs r4, #0\n" +
                    "str  r4, [r3]\n" +  # Reset `writeme`
                    "str  r4, [r2]\n" +  # Reset `outstat`
                    "bx   lr\n"  # Return from the interrupt, set by the interrupt calling convention
                    )

    def get_user_pc(self):
        """
        Return the "user PC", that is, the PC at the time an interrupt occurred.
        Returns None if we're not in an interrupt right now.

        :return:
        """
        if self.get_current_isr_num() > 0:
            sp = self._origin.get_register('sp')
            val = self._origin.read_memory(sp + 24)  # 24 is the offset of PC on the stack
            return val
        return None

    def get_current_isr_num(self):
        """
        If we're in an interrupt, return the current ISR number that we're in.

        :return:
        """
        # The bottom 8 bits of xPSR
        xpsr = self._origin.read_register("xpsr")
        if isinstance(xpsr, list):
            xpsr = xpsr[0]
        xpsr &= 0xff
        return xpsr

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
        self.log.info(f"_monitor_stub_base     = 0x{self._monitor_stub_base:08x}")
        self._monitor_stub_init = addr + 4*3
        self.log.info(f"_monitor_stub_init     = 0x{self._monitor_stub_init:08x}")
        self._monitor_stub_isr = addr + 0x1a
        self.log.info(f"_monitor_stub_isr      = 0x{self._monitor_stub_isr:08x}")
        self._monitor_stub_writeme = addr + 8
        self.log.info(f"_monitor_stub_writeme  = 0x{self._monitor_stub_writeme:08x}")
        self._monitor_stub_state = addr + 4
        self.log.info(f"_monitor_stub_outstat  = 0x{self._monitor_stub_state:08x}")

        # Pivot VTOR, if needed
        # On CM0, you can't, so don't.
        self.original_vtor = self.get_vtor()
        assert self.original_vtor != vtor, "VTOR is already set to the desired value."

        self.set_vtor(vtor)
        self.log.info(f"Validate new VTOR address 0x{self.get_vtor():8x}")

        # Sometimes, we need to gain access to the IVT (make it writable). Do that here.
        if getattr(self._origin, 'ivt_unlock', None) is not None:
            unlock_addr, unlock_val = self._origin.ivt_unlock
            self._origin.write_memory(unlock_addr, 4, unlock_val)

        self.log.info(f"Inserting the stub ...")
        # Inject the stub
        self._origin.inject_asm(self.MONITOR_STUB, self._monitor_stub_base)

        self.log.info(f"Setting up IVT...")
        self.original_vt = self._origin.read_memory(self.original_vtor, size=4, num_words=num_isr)

        # Set the IVT to our stub but DON'T wipe out the 0'th position.
        self._origin.write_memory(vtor, value=self.original_vt, size=4)
        for interrupt_num in range(1, num_isr):
            self.set_isr(interrupt_num, self._monitor_stub_isr + 1)  # +1 for thumb mode

        if self._origin.state != TargetStates.STOPPED:
            self.log.critical(
                "Not setting PC to the monitor stub; Target not stopped")
        else:
            self._origin.regs.pc = self._monitor_stub_init
            self.log.warning(f"Updated PC to 0x{self._origin.regs.pc:8x}")

    def inject_exc_return(self):
        if not self._monitor_stub_base:
            self.log.error(
                "You need to inject the monitor stub before you can inject exc_returns")
            return False
        # We can just BX LR for now.
        return self._origin.write_memory(address=self._monitor_stub_writeme, size=4, value=1)

    def get_stub_state(self) -> HWInterruptState:
        state = self._origin.read_memory(self._monitor_stub_state, size=4)
        return HWInterruptState(state)

    def dispatch_exception_packet(self):
        # To read the xPSR register containing the ISR number we need to halt the target.
        self._origin.stop()
        int_num = self.get_current_isr_num()
        self._origin.cont()

        self.log.warning(f"Dispatching exception for interrupt number {int_num}")

        msg = TargetInterruptEnterMessage(self._origin, self.msg_counter, interrupt_num=int_num, isr_addr=self.original_vt[int_num])
        self.msg_counter += 1
        self._avatar_fast_queue.put(msg)

    def run(self):
        TICK_DELAY = 0.0001
        self.log.warning("Starting ARMV7InterruptProtocol thread")
        last_hw_state = HWInterruptState.HW_INTERRUPT_STATE_UNDEF
        try:
            while not (self.avatar._close.is_set() or self._close.is_set()):
                if self._monitor_stub_state is None:
                    sleep(TICK_DELAY)
                    continue

                # self.log.debug(f"ARMV7InterruptProtocol protocol tick")
                hw_state = self.get_stub_state()
                if hw_state != last_hw_state:
                    self.log.warning(f"HW state changed to {hw_state}")
                    last_hw_state = hw_state
                    if hw_state == HWInterruptState.HW_INTERRUPT_STATE_INT:
                        self.dispatch_exception_packet()
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
