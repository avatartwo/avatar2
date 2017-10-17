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
from avatar2.message import AvatarMessage, UpdateStateMessage, BreakpointHitMessage, RemoteInterruptEnterMessage
from avatar2.protocols.openocd import OpenOCDProtocol

# ARM System Control Block
SCB_CPUID = 0xe000ed00 # What is it
SCB_STIR  = 0xe000ef00 # Send interrupts here
SCB_VTOR =  0xe000ed08 # Vector Table offset register

# NVIC stuff
NVIC_ISER0 = 0xe000e100


# CoreSight Constant Addresses
RCC_APB2ENR      = 0x40021018
AFIO_MAPR        = 0x40010004
DBGMCU_CR        = 0xe0042004
COREDEBUG_DEMCR  = 0xe000edfc
TPI_ACPR         = 0xe0040010
TPI_SPPR         = 0xe00400f0
TPI_FFCR         = 0xe0040304
DWT_CTRL         = 0xe0001000
ITM_LAR          = 0xe0000fb0
ITM_TCR          = 0xe0000e80
ITM_TER          = 0xe0000e00
ETM_LAR          = 0xe0041fb0
ETM_CR           = 0xe0041000
ETM_TRACEIDR     = 0xe0041200
ETM_TECR1        = 0xe0041024
ETM_FFRR         = 0xe0041028
ETM_FFLR         = 0xe004102c



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
        self.log = logging.getLogger('%s.%s' %
                                     (origin.log.name, self.__class__.__name__)
                                     ) if origin else \
            logging.getLogger(self.__class__.__name__)
        Thread.__init__(self)

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
    
    def set_vtor(self, addr):
        return self._origin.write_memory(SCB_VTOR, 4, addr)
    
    def get_isr(self, interrupt_num):
        return self._origin.read_memory(self.get_vtor() + (interrupt_num * 4), 4)

    def set_isr(self, interrupt_num, addr):
        return self._origin.write_memory(self.get_vtor() + (interrupt_num * 4), 4, addr)

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
        print("Implementer %#08x, Variant %#08x, Part %#08x, Rev %#08x" % (impl, vari, part, rev))

    def shutdown(self):
        self.stop()

    def connect(self):
        if not isinstance(self._origin.protocols.monitor, OpenOCDProtocol):
            raise Exception(("CoreSightProtocol requires OpenOCDProtocol ")
                            ("to be present."))

    def has_bits_to_read(self, b, n):
        return b.len - b.pos > n

    def enable_interrupts(self):
        try:
            self.log.info("Starting CoreSight Protocol")
            if not isinstance(self._origin.protocols.monitor, OpenOCDProtocol):
                raise Exception("CoreSightProtocol requires OpenOCDProtocol to be present.")
            openocd = self._origin.protocols.monitor
            self.log.debug("Resetting target")
            openocd.reset()
            # Enable TCL tracing
            if not openocd.trace_enabled.is_set():
                openocd.enable_trace()
                if not openocd.trace_enabled.is_set():
                    self.log.error("Can't get trace events without tcl_trace! aborting...")
                    return False
            self.trace_queue = openocd.trace_queue
            # Enable the TPIO output to the FIFO
            self.log.debug("Enabling TPIU output events")
            openocd.execute_command('tpiu config internal - uart off 32000000')
            # Enable the DWT to get interrupts
            self.log.debug("Enabling exceptions in DWT")
            openocd.execute_command("setbits $COREDEBUG_DEMCR 0x1000000") # Enable access to trace regs - set TRCENA to 1
            openocd.execute_command("mww $DWT_CTRL 0x40010000")  # exc trace only
            self.log.debug("Enabling ITM passthrough of DWT events")
            # Enable the ITM to pass DWT output to the TPIU
            openocd.execute_command("mww $ITM_LAR 0xC5ACCE55")
            openocd.execute_command("mww $ITM_TCR 0x0000000d")  # TraceBusID 1, enable dwt/itm/sync
            openocd.execute_command("mww $ITM_TER 0xffffffff")  # Enable all stimulus ports
            # Run our little daemon thingy
            self.log.debug("Starting interrupt handling thread")
            self.daemon=True
            self.start()
            #self.inject_monitor_stub()
        except:
            self.log.exception("Error starting Coresight")


    MONITOR_STUB = """
    writeme: .word 0x0
    stub: mov r3, pc
    sub r5, r3, #8
    ldr r0, [r5]
    mov r1, #0
    cmp r1, r0
    beq stub
    mov r4, r15
    add r4, #8
    str r1, [r5]
    mov r15, r0
    """

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
        #self._origin.stop()
        # Pivot VTOR
        if self.get_vtor() == 0:
            self.set_vtor(vtor)
        # put the stub
        self._origin.inject_asm(self.MONITOR_STUB, addr)
        # wreck the IVT
        for x in range(0, 254):
            self.set_isr(x, addr+5)
        self._origin.regs.pc = addr + 4
        #for x in range(0,3):
        #    iser = NVIC_ISER0 + 4 * x
        #    self._origin.write_memory(iser, 4, 0xffffffff)


    def inject_exc_return(exc_return, flag_addr=0x20001234):
        return nucleo.write_memory(flag_addr, 4, exc_return)


    def dispatch_exception_packet(self, packet):
        int_num = ((ord(packet[1]) & 0x01) << 8) | ord(packet[0])
        transition_type = (ord(packet[1]) & 0x30) >> 4

        msg = RemoteInterruptEnterMessage(self._origin, transition_type,
                                          int_num)
        self._avatar_fast_queue.put(msg)

    def run(self):
        DWT_PKTSIZE_BITS = 24
        trace_re = re.compile("type target_trace data ([0-9a-f]+)")
        self.log.debug("Starting interrupt thread")
        try:
            while not self._close.is_set():
                if self._close.is_set():
                    break
                # OpenOCD gives us target_trace events packed with many, many packets.
                # Get them out, then do them packet-at-a-time
                if not self.has_bits_to_read(self.trace_buffer, DWT_PKTSIZE_BITS):
                    # get some more data
                    if self.trace_queue.empty():
                        # make sure we can see the shutdown flag
                        continue
                    new_data = self.trace_queue.get()
                    m = trace_re.match(new_data)
                    if m:
                        self.trace_buffer.append("0x" + m.group(1))
                    else:
                        raise ValueError("Got a really weird trace packet " + new_data)
                if not self.has_bits_to_read(self.trace_buffer, DWT_PKTSIZE_BITS):
                    continue
                try:
                    pkt = self.trace_buffer.peek(DWT_PKTSIZE_BITS).bytes
                except ReadError:
                    self.log.error("Fuck you length is " + repr(len(self.trace_buffer)) + " " + repr(DWT_PKTSIZE_BITS))
                if ord(pkt[0]) == 0x0E:  # exception packets
                    pkt = pkt[1:]
                    self.dispatch_exception_packet(pkt)
                    # eat the bytes
                    self.trace_buffer.read(DWT_PKTSIZE_BITS)
                # the first byte didn't match, rotate it out
                else:
                    self.trace_buffer.read(8)
        except:
            self.log.exception("Error processing trace")
        self._closed.set()
        self.log.debug("Interrupt thread exiting...")

    def stop(self):
        """Stops the listening thread. Useful for teardown of the target"""
        self._close.set()
        self._closed.wait()
