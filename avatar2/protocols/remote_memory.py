import logging

from enum import Enum
from os import O_WRONLY, O_RDONLY
from threading import Thread, Event
from ctypes import Structure, c_uint32, c_uint64

from posix_ipc import MessageQueue, ExistentialError

from avatar2.message import RemoteMemoryReadMessage, RemoteMemoryWriteMessage


class Operation(Enum):
    READ = 0
    WRITE = 1


class RemoteMemoryReq(Structure):
    _fields_ = [
        ('id', c_uint64),
        ('pc', c_uint64),
        ('address', c_uint64),
        ('value', c_uint64),
        ('size', c_uint32),
        ('operation', c_uint32)
    ]


class RemoteMemoryResp(Structure):
    _fields_ = [
        ('id', c_uint64),
        ('value', c_uint64),
        ('success', c_uint32)
    ]


class RemoteMemoryRequestListener(Thread):
    def __init__(self, rx_queue, avatar_queue, origin):
        super(RemoteMemoryRequestListener, self).__init__()
        self._rx_queue = rx_queue
        self._avatar_queue = avatar_queue
        self._origin = origin
        self._close = Event()
        self._closed = Event()
        self._close.clear()
        self._closed.clear()
        self.log = logging.getLogger('%s.%s' %
                                     (origin.log.name, self.__class__.__name__)
                                     ) if origin else \
            logging.getLogger(self.__class__.__name__)

    def run(self):
        while True:
            if self._close.is_set():
                break

            request = None
            try:
                request = self._rx_queue.receive(0.5)
            except:
                continue

            req_struct = RemoteMemoryReq.from_buffer_copy(request[0])

            if Operation(req_struct.operation) == Operation.READ:
                self.log.debug(("Received RemoteMemoryRequest."
                                "Read from 0x%x at 0x%x") %
                                (req_struct.address, req_struct.pc))
                MemoryForwardMsg = RemoteMemoryReadMessage(self._origin,
                                                           req_struct.id,
                                                           req_struct.pc,
                                                           req_struct.address,
                                                           req_struct.size)
            elif Operation(req_struct.operation) == Operation.WRITE:
                self.log.debug(("Received RemoteMemoryRequest."
                                "Write to 0x%x at 0x%x") %
                                (req_struct.address, req_struct.pc))
                MemoryForwardMsg = RemoteMemoryWriteMessage(self._origin,
                                                            req_struct.id,
                                                            req_struct.pc,
                                                            req_struct.address,
                                                            req_struct.value,
                                                            req_struct.size)
            else:
                raise ValueError("Received Message with unkown operation %d" %
                                 req_struct.operation)

            self._avatar_queue.put(MemoryForwardMsg)

        self._closed.set()

    def stop(self):
        self._close.set()
        self._closed.wait()


class RemoteMemoryProtocol(object):
    """
    This class listens to memoryforward requests and lifts them to avatar
    messages. Likewise it can be directed to emit memoryforward-response
    messages

    :param rx_queue_name: Name of the queue for receiving
    :param tx_queue_name: Name of the queue for sending
    :param avatar_queue:  Queue to dispatch received requests to
    :param origin:        Reference to the Target utilizing this protocol

    """

    def __init__(self, rx_queue_name, tx_queue_name,
                 avatar_queue, origin=None):
        self._rx_queue = None
        self._tx_queue = None
        self._rx_listener = None

        self.rx_queue_name = rx_queue_name
        self.tx_queue_name = tx_queue_name
        self._avatar_queue = avatar_queue
        self._origin = origin

        self.log = logging.getLogger('%s.%s' %
                                     (origin.log.name, self.__class__.__name__)
                                     ) if origin else \
            logging.getLogger(self.__class__.__name__)

    def connect(self):
        """
        Connect to the message queues for remote memory

        :return True on success, else False
        """
        try:
            self._rx_queue = MessageQueue(self.rx_queue_name, flags=O_RDONLY,
                                          read=True, write=False)
        except Exception as e:
            self.log.exception("Unable to create rx_queue:")
            return False

        try:
            self._tx_queue = MessageQueue(self.tx_queue_name, flags=O_WRONLY,
                                          read=False, write=True)
        except Exception as e:
            self.log.exception("Unable to create tx_queue:")
            self._rx_queue.close()
            return False
        self._rx_listener = RemoteMemoryRequestListener(self._rx_queue,
                                                        self._avatar_queue,
                                                        self._origin)
        self._rx_listener.daemon = True
        self._rx_listener.start()
        self.log.info("Successfully connected rmp")
        return True

    def __del__(self):
        self.shutdown()

    def shutdown(self):
        if self._rx_listener:
            self._rx_listener.stop()
            self._rx_listener = None
        if self._rx_queue:
            try:
                self._rx_queue.unlink()
                self._rx_queue.close()
                self._rx_queue = None
            except ExistentialError:
                self.log.warning("Tried to close/unlink non existent rx_queue")
        if self._tx_queue:
            try:
                self._tx_queue.unlink()
                self._tx_queue.close()
                self._tx_queue = None
            except ExistentialError:
                self.log.warning("Tried to close/unlink non existent tx_queue")

    def send_response(self, id, value, success):
        response = RemoteMemoryResp(id, value, success)
        try:
            self._tx_queue.send(response)
            self.log.debug("Send RemoteMemoryResponse with id %d, %x" % (id, value))
            return True
        except Exception as e:
            self.log.error("Unable to send response: %s" % e)
            return False
