import logging

from os import O_WRONLY, O_RDONLY
from threading import Thread, Event, Condition
from ctypes import Structure, c_uint32, c_uint64
from enum import Enum
from posix_ipc import MessageQueue, ExistentialError

from avatar2.message import RemoteInterruptEnterMessage
from avatar2.message import RemoteInterruptExitMessage
from avatar2.targets import QemuTarget

# NVIC stuff
NVIC_ISER0 = 0xe000e100


class RINOperation(Enum):
    ENTER = 0
    EXIT = 1


class V7MRemoteInterruptNotification(Structure):
    _fields_ = [
        ('id', c_uint64),
        ('num_irq', c_uint32),
        ('operation', c_uint32),
        ('type', c_uint32)
    ]

    def __reduce__(self):
        # Define the mapping of desired field names to actual field names
        field_mapping = {'num-irq': 'num_irq'}

        # Create a dictionary to store the serialized state
        state = {}

        # Populate the state dictionary with the desired field names and values
        for desired_name, actual_name in field_mapping.items():
            state[desired_name] = getattr(self, actual_name)

        # Return a tuple of callable and arguments for object reconstruction
        return self.__class__, (state,)

    @classmethod
    def from_state(cls, state):
        # Define the reverse mapping of desired field names to actual field names
        field_mapping = {'num-irq': 'num_irq'}

        # Create an instance of the class
        instance = cls()

        # Retrieve field values from the serialized state using the desired field names
        # and assign them to the corresponding actual field names in the class instance
        for desired_name, actual_name in field_mapping.items():
            setattr(instance, actual_name, state[desired_name])

        return instance


class V7MInterruptNotificationAck(Structure):
    _fields_ = [
        ('id', c_uint64),
        ('success', c_uint32),
        ('operation', c_uint32),
    ]


class QEmuARMV7MInterruptProtocol(Thread):
    """
    This protocol has two purposes: 
        a) injecting interrupts into an analysis target
        b) extracting interrupt exits and putting them into the avatar queue
    (b) is necessary in cases where two targets need to be synched on the
        interrupts.
        The way a v7m-nvic implements interrupt return is to put a magic value
        into $pc, and the hardware does the actual magic of popping from the
        interrupt stack and restoring the context. 
        However, the magic value defines the type of the interrupt return,
        and is hence synchronized on interrupt exit, alongside with the
        interrupt number
    :param origin:        Reference to the Target utilizing this protocol
    :param rx_queue_name: Name of the queue for receiving
    :param tx_queue_name: Name of the queue for sending
    """

    def __init__(self, origin, rx_queue_name, tx_queue_name):
        super(self.__class__, self).__init__()
        self._rx_queue_name = rx_queue_name
        self._tx_queue_name = tx_queue_name
        self._rx_queue = None
        self._tx_queue = None
        self._avatar_queue = origin.avatar.queue
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
        while not self._close.is_set():

            request = None
            try:
                request = self._rx_queue.receive(0.5)
            except:
                continue

            req_struct = V7MRemoteInterruptNotification.from_buffer_copy(
                request[0])

            if RINOperation(req_struct.operation) == RINOperation.ENTER:
                msg = RemoteInterruptEnterMessage(self._origin, req_struct.id,
                                                  req_struct.num_irq)
                self.log.warning(
                    "Received an InterruptEnterRequest for irq %d (%x)" %
                    (req_struct.num_irq, req_struct.type))
            elif RINOperation(req_struct.operation) == RINOperation.EXIT:
                msg = RemoteInterruptExitMessage(self._origin, req_struct.id,
                                                 req_struct.type,
                                                 req_struct.num_irq)
                self.log.warning(
                    "Received an InterruptExitRequest for irq %d (%x)" %
                    (req_struct.num_irq, req_struct.type))

            else:
                msg = None
                raise Exception(("Received V7MRemoteInterrupt Notification with"
                                 "unknown operation type %d") %
                                req_struct.operation)

            self._avatar_queue.put(msg)

        self._closed.set()

    def stop(self):
        self._close.set()
        self._closed.wait()

    def enable_interrupts(self):
        if isinstance(self._origin, QemuTarget):
            # TODO: Make this more clean, i.e., check for remote memory
            rmem_rx_qname = self._origin.protocols.remote_memory.rx_queue_name
            rmem_tx_qname = self._origin.protocols.remote_memory.tx_queue_name
            # the tx-queue for qemu is the rx-queue for avatar and vice versa
            self._origin.protocols.monitor.execute_command(
                'avatar-armv7m-enable-irq',
                {'irq-rx-queue-name': self._tx_queue_name,
                 'irq-tx-queue-name': self._rx_queue_name,
                 'rmem-rx-queue-name': rmem_tx_qname,
                 'rmem-tx-queue-name': rmem_rx_qname
                 }
            )
        else:
            raise Exception("V7MInterruptProtocol is not implemented for %s" %
                            self._origin.__class__)

        try:
            self._rx_queue = MessageQueue(self._rx_queue_name, flags=O_RDONLY,
                                          read=True, write=False)
        except Exception as e:
            self.log.error("Unable to create rx_queue (name=%s): %s" % (self._rx_queue_name, e))
            return False

        try:
            self._tx_queue = MessageQueue(self._tx_queue_name, flags=O_WRONLY,
                                          read=False, write=True)
        except Exception as e:
            self.log.error("Unable to create tx_queue: %s (name=%s)" % (self._tx_queue_name, e))
            self._rx_queue.close()
            return False

        self.daemon = True
        self.start()
        self.log.info("Enabled Interrupt Forwarding for %s" % self._origin)
        return True

    def ignore_interrupt_return(self, interrupt_number):
        if isinstance(self._origin, QemuTarget):
            self.log.info(
                "Disable handling of irq return for %d" % interrupt_number)
            self._origin.protocols.monitor.execute_command(
                'avatar-armv7m-ignore-irq-return',
                {'num-irq': interrupt_number}
            )

    def unignore_interrupt_return(self, interrupt_number):
        if isinstance(self._origin, QemuTarget):
            self.log.info(
                "Re-enable handling of irq return for %d" % interrupt_number)
            self._origin.protocols.monitor.execute_command(
                'avatar-armv7m-unignore-irq-return',
                {'num-irq': interrupt_number}
            )

    def inject_interrupt(self, interrupt_number, cpu_number=0):
        if isinstance(self._origin, QemuTarget):
            self.log.info("Injecting interrupt %d" % interrupt_number)
            self._origin.protocols.monitor.execute_command(
                'avatar-armv7m-inject-irq',
                {'num-irq': interrupt_number, 'num-cpu': cpu_number}
            )

    def set_vector_table_base(self, base, cpu_number=0):
        if isinstance(self._origin, QemuTarget):
            self.log.info("Setting vector table base to 0x%x" % base)
            self._origin.protocols.monitor.execute_command(
                'avatar-armv7m-set-vector-table-base',
                {'base': base, 'num-cpu': cpu_number}
            )

    def send_interrupt_exit_response(self, id, success):
        response = V7MInterruptNotificationAck(id, success,
                                               RINOperation.EXIT.value)

        try:
            self._tx_queue.send(response)
            self.log.info("Send RemoteInterruptExitResponse with id %d" % id)
            return True
        except Exception as e:
            self.log.error("Unable to send response: %s" % e)
            return False

    def send_interrupt_enter_response(self, id, success):
        response = V7MInterruptNotificationAck(id, success,
                                               RINOperation.ENTER.value)
        try:
            self._tx_queue.send(response)
            self.log.info("Send RemoteInterruptEnterResponse with id %d" % id)
            return True
        except Exception as e:
            self.log.error("Unable to send response: %s" % e)
            return False

    def get_enabled_interrupts(self, iser_num: int = 0):
        enabled_interrupts = self._origin.read_memory(NVIC_ISER0 + iser_num * 4, size=4)
        return enabled_interrupts

    def set_enabled_interrupts(self, enabled_interrupts_bitfield: int, iser_num: int = 0):
        self.log.warning(f"Setting enabled interrupts to 0x{enabled_interrupts_bitfield:x}")
        self._origin.write_memory(NVIC_ISER0 + iser_num * 4, size=4, value=enabled_interrupts_bitfield)

    def __del__(self):
        self.shutdown()

    def shutdown(self):
        self.stop()
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
