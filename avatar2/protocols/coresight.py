import sys
from threading import Thread, Event, Condition
from struct import pack, unpack
from codecs import encode
import logging
import os
import re
from bitstring import BitStream, ReadError
from binascii import unhexlify
import pygdbmi.gdbcontroller
from .openocd import OpenOCDProtocol

if sys.version_info < (3, 0):
    import Queue as queue
    # __class__ = instance.__class__
else:
    import queue

from avatar2.archs.arm import ARM
from avatar2.targets import TargetStates
from avatar2.message import AvatarMessage, UpdateStateMessage, \
    BreakpointHitMessage, RemoteInterruptEnterMessage
from avatar2.protocols.openocd import OpenOCDProtocol

logger = logging.getLogger(__name__)

# ARM System Control Block
SCB_CPUID = 0xe000ed00  # What is it
SCB_STIR = 0xe000ef00  # Send interrupts here
SCB_VTOR = 0xe000ed08  # Vector Table offset register

# NVIC stuff
NVIC_ISER0 = 0xe000e100

# CoreSight Constant Addresses
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


class CoreSightProtocol(Thread):
    def __init__(self, avatar, origin):
        self.avatar = avatar
        self._avatar_queue = avatar.queue
        self._avatar_fast_queue = avatar.fast_queue
        self._origin = origin
        self.trace_queue = None
        self.trace_buffer = BitStream()
        self._close = Event()
        self._closed = Event()
        self._close.clear()
        self._closed.clear()
        self._sync_responses_cv = Condition()
        self._last_exec_token = 0
        # logger = logging.getLogger('%s.%s' %
        #                              (origin.log.name, self.__class__.__name__)
        #                              ) if origin else \
        #     logging.getLogger(self.__class__.__name__)
        self._monitor_stub_base = None
        self._monitor_stub_isr = None
        self._monitor_stub_loop = None
        self._monitor_stub_writeme = None
        Thread.__init__(self)
        self.daemon = True

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
        iser_num = interrupt_number >> 5
        iser_addr = NVIC_ISER0 + (iser_num * 4)
        # iser_off = interrupt_number % 32
        # iser_val = self._origin.read_memory(iser_addr, 4)
        iser_val = ((1 << interrupt_number) & 0x1F)
        # iser_val |= 0x1 << iser_off
        self._origin.write_memory(iser_addr, 4, iser_val)

    def get_vtor(self):
        return self._origin.read_memory(SCB_VTOR, 4)

    def get_ivt_addr(self):
        if getattr(self._origin, 'ivt_address', None) is not None:
            return self._origin.ivt_address
        else:
            return self.get_vtor()

    def set_vtor(self, addr):
        return self._origin.write_memory(SCB_VTOR, 4, addr)

    def get_isr(self, interrupt_num):
        return self._origin.read_memory(
            self.get_ivt_addr() + (interrupt_num * 4), 4)

    def set_isr(self, interrupt_num, addr):
        return self._origin.write_memory(
            self.get_ivt_addr() + (interrupt_num * 4), 4, addr)

    def cpuid(self):
        c = self._origin.read_memory(SCB_CPUID, 4, 1)
        print("CPUID: %#08x" % c)
        if (0x412fc230 & 0x000f0000) >> 16 == 0xf:
            print("Found ARM Cortex CPUID")
        else:
            return
        impl = (c >> 24)
        vari = (c & 0x00f00000) >> 20
        part = (c & 0x0000fff0) >> 4
        rev = (c & 0x0000000f)
        print("Implementer %#08x, Variant %#08x, Part %#08x, Rev %#08x" % (
            impl, vari, part, rev))

    def shutdown(self):
        if self.is_alive() is True:
            self.stop()

    def connect(self):
        if not isinstance(self._origin.protocols.monitor, OpenOCDProtocol):
            raise Exception(("CoreSightProtocol requires OpenOCDProtocol ")
                            ("to be present."))

    def has_bits_to_read(self, b, n):
        return b.len - b.pos > n

    def enable_interrupts(self, use_tcl_tracing=False, use_stub=True):
        try:
            logger.info("Starting CoreSight Protocol")
            if not isinstance(self._origin.protocols.monitor, OpenOCDProtocol):
                raise Exception(
                    "CoreSightProtocol requires OpenOCDProtocol to be present.")
            openocd = self._origin.protocols.monitor
            logger.debug("Resetting target")
            openocd.reset()

            if use_tcl_tracing:
                # Enable TCL tracing
                if not openocd.trace_enabled.is_set():
                    openocd.enable_trace()
                    if not openocd.trace_enabled.is_set():
                        logger.error(
                            "Can't get trace events without tcl_trace! aborting...")
                        return False
                self.trace_queue = openocd.trace_queue
                # Enable the TPIO output to the FIFO
                logger.debug("Enabling TPIU output events")
                openocd.execute_command(
                    'tpiu config internal - uart off 32000000')
                # Enable the DWT to get interrupts
                logger.debug("Enabling exceptions in DWT")
                openocd.execute_command(
                    "setbits $COREDEBUG_DEMCR 0x1000000")  # Enable access to trace regs - set TRCENA to 1
                openocd.execute_command(
                    "mww $DWT_CTRL 0x40010000")  # exc trace only
                logger.debug("Enabling ITM passthrough of DWT events")
                # Enable the ITM to pass DWT output to the TPIU
                openocd.execute_command("mww $ITM_LAR 0xC5ACCE55")
                openocd.execute_command(
                    "mww $ITM_TCR 0x0000000d")  # TraceBusID 1, enable dwt/itm/sync
                openocd.execute_command(
                    "mww $ITM_TER 0xffffffff")  # Enable all stimulus ports
                # Run our little daemon thingy
                logger.debug("Starting interrupt handling thread")
                self.daemon = True
                self.start()

            elif use_stub:
                self.inject_monitor_stub()
        except:
            logger.exception("Error starting Coresight")

    """
    What this does:
    Hang in a loop at `loop`
    When an interrupt comes, go to `stub`
    At `stub`, load `writeme`, if it's not zero, reset it, and jump to the written value.
    This lets us inject exc_return values into the running program
    """
    # MONITOR_STUB = """
    # loop: b loop
    # nop
    # mov r2, pc
    # ldr r1, [r2, #16]
    # stub:
    # ldr r0, [r2, #12]
    # cmp r1, r0
    # beq stub
    # str r1, [r2, #12]
    # bx r0
    # nop
    # writeme: .word 0xffffffff
    # loadme: .word 0xffffffff
    # """
    # str r2, [r1]

    MONITOR_STUB = """
    dcscr:   .word 0xe000edf0
    haltme:  .word 0xA05F0003
    writeme: .word 0x00000000
    init:
    ldr r1, =dcscr
    ldr r2, =haltme
    ldr r3, =writeme
    ldr r1, [r1]
    ldr r2, [r2]
    loop: b loop
    stub: 
    nop
    intloop:
    ldr r4, [r3]
    cmp r4, #0
    beq intloop
    ldr r4, #0
    str r4, [r3]
    bx lr
    """

    def get_user_pc(self):
        """
        Return the "user PC", that is, the PC at the time an interrupt occurred.
        Returns None if we're not in an interrupt right now.

        :return:
        """
        if self.get_current_isr_num() > 0:
            sp = self._origin.get_register('sp')
            val = self._origin.read_memory(sp - 24)
            return val
        return None

    def get_current_isr_num(self):
        """
        If we're in an interrupt, return the current ISR number that we're in.

        :return:
        """
        # The bottom 8 bits of xPSR
        xpsr = self._origin.read_register("xPSR")
        xpsr &= 0xff
        return xpsr

    def inject_monitor_stub(self, addr=0x20001234, vtor=0x20002000):
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
        logger.info(
            "Injecting monitor stub. (IVT: %s, %s, %s)"
            ")" % (self.get_ivt_addr(), self.get_vtor(), vtor))

        self._monitor_stub_base = addr
        self._monitor_stub_loop = addr + 12
        self._monitor_stub_isr = addr + 25
        self._monitor_stub_writeme = addr + 8
        # Pivot VTOR, if needed
        # On CM0, you can't, so don't.
        if getattr(self._origin, 'ivt_address', None) is None:
            if self.get_vtor() == 0:
                self.set_vtor(vtor)
        # Sometimes, we need to gain access to the IVT (make it writable). Do that here.
        if getattr(self._origin, 'ivt_unlock', None) is not None:
            unlock_addr, unlock_val = self._origin.ivt_unlock
            self._origin.write_memory(unlock_addr, 4, unlock_val)
        # put the stub
        self._origin.inject_asm(self.MONITOR_STUB, self._monitor_stub_base)
        # wreck the IVT
        # ...oh but don't wipe out the 0'th position.
        for x in range(1, 254):
            self.set_isr(x, self._monitor_stub_isr)
        if self._origin.state != TargetStates.STOPPED:
            logger.warning(
                "Not setting PC to the monitor stub; Target not stopped")
        else:
            self._origin.regs.pc = self._monitor_stub_loop

    def inject_exc_return(self, exc_return):
        if not self._monitor_stub_base:
            logger.error(
                "You need to inject the monitor stub before you can inject exc_returns")
            return False
        # We can just BX LR for now.
        return self._origin.write_memory(self._monitor_stub_writeme, 4, 1)

    def dispatch_exception_packet(self, packet):
        int_num = ((ord(packet[1]) & 0x01) << 8) | ord(packet[0])
        transition_type = (ord(packet[1]) & 0x30) >> 4

        msg = RemoteInterruptEnterMessage(self._origin, transition_type,
                                          int_num)
        self._avatar_fast_queue.put(msg)

    def run(self):
        DWT_PKTSIZE_BITS = 24
        trace_re = re.compile("type target_trace data ([0-9a-f]+)")
        logger.debug("Starting interrupt thread")
        try:
            while not self._close.is_set():
                if self._close.is_set():
                    break
                # OpenOCD gives us target_trace events packed with many, many packets.
                # Get them out, then do them packet-at-a-time
                if not self.has_bits_to_read(self.trace_buffer,
                                             DWT_PKTSIZE_BITS):
                    # get some more data
                    if self.trace_queue.empty():
                        # make sure we can see the shutdown flag
                        continue
                    new_data = self.trace_queue.get()
                    m = trace_re.match(new_data)
                    if m:
                        self.trace_buffer.append("0x" + m.group(1))
                    else:
                        raise ValueError(
                            "Got a really weird trace packet " + new_data)
                if not self.has_bits_to_read(self.trace_buffer,
                                             DWT_PKTSIZE_BITS):
                    continue
                try:
                    pkt = self.trace_buffer.peek(DWT_PKTSIZE_BITS).bytes
                except ReadError:
                    logger.error("Fuck you length is " + repr(
                        len(self.trace_buffer)) + " " + repr(DWT_PKTSIZE_BITS))
                if ord(pkt[0]) == 0x0E:  # exception packets
                    pkt = pkt[1:]
                    self.dispatch_exception_packet(pkt)
                    # eat the bytes
                    self.trace_buffer.read(DWT_PKTSIZE_BITS)
                # the first byte didn't match, rotate it out
                else:
                    self.trace_buffer.read(8)
        except:
            logger.exception("Error processing trace")
        self._closed.set()
        logger.debug("Interrupt thread exiting...")

    def stop(self):
        """Stops the listening thread. Useful for teardown of the target"""
        self._close.set()
        self._closed.wait()
