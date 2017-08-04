import sys
from threading import Thread, Event, Condition
from struct import pack, unpack
from codecs import encode
import logging
import pygdbmi.gdbcontroller
from os import mkfifo

if sys.version_info < (3, 0):
    import Queue as queue
    # __class__ = instance.__class__
else:
    import queue

from avatar2.archs.arm import ARM
from avatar2.targets import TargetStates
from avatar2.message import AvatarMessage, UpdateStateMessage, BreakpointHitMessage


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




class CoreSightResponseListener(Thread):
    """
    """

    def __init__(self, coresight_protocol, fifo_name,  avatar_queue, origin=None):
        super(CoreSightResponseListener, self).__init__()
        self._protocol = coresight_protocol
        self._token = -1
        self._async_responses = queue.Queue() if avatar_queue is None \
            else avatar_queue
        self._coresight = coresight_protocol
        self._coresight_fifo = coresight_fifo
        self._close = Event()
        self._closed = Event()
        self._close.clear()
        self._closed.clear()
        self._sync_responses_cv = Condition()
        self._last_exec_token = 0
        self._origin = origin
        self.log = logging.getLogger('%s.%s' %
                                     (origin.log.name, self.__class__.__name__)
                                     ) if origin else \
            logging.getLogger(self.__class__.__name__)


    def dispatch_exception_packet(self, packet):
        int_num = (ord(packet[1] & 0x01) << 8) | ord(packet[0])
        transition_type = (ord(packet[1]) & 0x30) >> 4

        msg = ForwardInterruptMessage(self._origin, transition_type, int_num)
        self._avatar_queue.put(msg)



    def run(self):
        fifo = open(fifo_name, 'rb')
        while 1:
            if self._close.is_set():
                break

            try:
                fifo.read(1)
		if ord(byte) == 0x0E: #fetch exception packets
                    packet = fifo.read(2)
                    self.dispatch_exception_packet(packet)
            except:
                continue
                # Add some parsing here
        self._closed.set()

    def stop(self):
        """Stops the listening thread. Useful for teardown of the target"""
        self._close.set()
        self._closed.wait()


class CoreSightProtocol(object):
    """
    """

    def __init__(
            self,
            avatar_queue=None,
            origin=None
            fifo_name=None):
        self._communicator = CoreSightResponseListener(self, origin, fifo_name,
                                                       avatar_queue)
        self._avatar_queue = avatar_queue
        self._origin = origin
        self.log = logging.getLogger('%s.%s' %
                                     (origin.log.name, self.__class__.__name__)
                                     ) if origin else \
            logging.getLogger(self.__class__.__name__)

    def __del__(self):
        self.shutdown()

    def shutdown(self):
        if self._communicator is not None:
            self._communicator.stop()
            self._communicator = None
        if self._gdbmi is not None:
            self._gdbmi.exit()
            self._gdbmi = None

    def connect(self):
        if not instanceof(self._origin._monitor_protocol, OpenOCDProtocol):
            raise Exception(("CoreSightProtocol requires OpenOCDProtocol ")
                            ("to be present."))


    def enable_interrupts(self):
        if not instanceof(self._origin._monitor_protocol, OpenOCDProtocol):
            raise Exception(("CoreSightProtocol requires OpenOCDProtocol ")
                            ("to be present."))

        openocd = self._origin._monitor_protocol
        fifo = mkfifo(self.fifo_name)
        openocd.execute_command('tpiu config internal %s uart off 32000000' % 
                                self.fifo_name)
        
        #these are magic coresight writes, lets document them one day
        openocd.execute_command('setbits %d 0x1000000' % COREDEBUG_DEMCR)

        openocd.execute_command('mww %d 0x40010000' % DWT_CTRL)
        openocd.execute_command('mww %d 0xC5ACCE55' % ITM_LAR)
        openocd.execute_command('mww %d 0x0000000d' % ITM_TCR)
        openocd.execute_command('mww %d 0xffffffff' % ITM_TER)
        # todo setup the magic
        self._communicator.start()
