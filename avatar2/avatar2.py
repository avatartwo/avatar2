import sys

if sys.version_info < (3, 0):
    import Queue as queue
else:
    import queue

import atexit
import tempfile
import intervaltree
import logging
import signal

from os import path, makedirs
from threading import Thread, Event

from .archs.arm import ARM
from .memory_range import MemoryRange
from .message import *
from .peripherals import AvatarPeripheral
from .targets.target import TargetStates #TargetStates
from .watchmen import watch, Watchmen


class Avatar(Thread):
    """The Avatar-object is the main interface of avatar.
    Here we can set the different targets, and more

    :ivar arch:     architecture of all targets
    :ivar endness:  used endianness


    """

    def __init__(self, arch=ARM, output_directory=None):
        super(Avatar, self).__init__()

        
        self.shutdowned = False
        signal.signal(signal.SIGINT, self.sigint_wrapper)
        self.sigint_handler = self.shutdown
        atexit.register(self.shutdown)

        self.watchmen = Watchmen(self)
        self.arch = arch
        self.arch.init(self)
        self.targets = {}
        self.status = {}
        self.memory_ranges = intervaltree.IntervalTree()
        self.loaded_plugins = []

        # Setup output-dir and logging
        self.output_directory = (tempfile.mkdtemp(suffix="_avatar")
                                 if output_directory is None
                                 else output_directory)
        if not path.exists(self.output_directory):
            makedirs(self.output_directory)
        self.log = logging.getLogger('avatar')
        format = '%(asctime)s | %(name)s.%(levelname)s | %(message)s'
        logging.basicConfig(filename='%s/avatar.log' % self.output_directory,
                            level=logging.INFO, format=format)
        self.log.info("Initialized Avatar. Output directory is %s" %
                      self.output_directory)

        # Setup the avatarqueues and register default handler
        self._close = Event()
        self.queue = queue.Queue()
        self.fast_queue = queue.Queue()
        self.fast_queue_listener = AvatarFastQueueProcessor(self)
        self.message_handlers = { 
            BreakpointHitMessage: self._handle_breakpoint_hit_message,
            UpdateStateMessage: self._handle_update_state_message,
            RemoteMemoryReadMessage: self._handle_remote_memory_read_message,
            RemoteMemoryWriteMessage: self._handle_remote_memory_write_msg
        }
        self.daemon = True
        self.start()

    def shutdown(self):
        """
        Shuts down all targets and Avatar. Should be called at end of script
        in order to cleanly exit all spawned processes and threads
        """
        if self.shutdowned is True:
            return
        for t in self.targets.values():
            t.shutdown()
        for range in self.memory_ranges:
            if isinstance(range.data.forwarded_to, AvatarPeripheral):
                range.data.forwarded_to.shutdown()
        self.shutdowned = True

    def sigint_wrapper(self, signal, frame):
        self.log.info("Avatar Received SIGINT")
        self.sigint_handler()

    def load_plugin(self, name):
        plugin = __import__("avatar2.plugins.%s" % name,
                            fromlist=['avatar2.plugins'])
        plugin.load_plugin(self)
        self.loaded_plugins += [name]

    @watch('AddTarget')
    def add_target(self, backend, *args, **kwargs):
        """
        Adds a new target to the analyses

        :ivar backend: the desired backend. Implemented for now: qemu, gdb
        :kwargs:       those argument will be passed to the target-object itself
        :return:       The created TargetObject
        """
        target = backend(self, *args, **kwargs)
        self.targets[target.name] = target

        return target

    def get_target(self, name):
        """
        Retrieves a target of the analyses by it's name

        :param name: The name of the desired target
        :return:     The Target!
        """

        return self.targets.get(name, None)

    def get_targets(self):
        """
        A generator for all targets.
        """
        for target in self.targets.items():
            yield target

    def init_targets(self):
        """
        Inits all created targets
        """
        for t in self.get_targets():
            t[1].init()

    def add_memory_range(self, address, size, name=None, permissions='rwx',
                         file=None, file_offset=None, file_bytes=None,
                         forwarded=False, forwarded_to=None,emulate=None,
                         **kwargs):
        """
        Adds a memory range to avatar

        :param emulate:      Emulation function that will take name, address and size if set
        :param address:      Base-Address of the Range
        :param size:         Size of the range
        :param file:         A file backing this range, if applicable
        :param file_offset:  The offset within the file
        :param file_bytes:   Bytes of the file to be copied into memory
        :param forwarded:    Whether this range should be forwarded
        :param forwarded_to: If forwarded is true, specify the forwarding target
        """
        if emulate:
            python_peripheral = emulate(name, address, size, **kwargs)
            forwarded = True
            forwarded_to = python_peripheral
            kwargs.update({'python_peripheral': python_peripheral})

        if forwarded:
            kwargs.update({'qemu_name': 'avatar-rmemory'})
        m = MemoryRange(address, size, name=name, permissions=permissions,
                        file=file, file_offset=file_offset,
                        file_bytes=file_bytes, forwarded=forwarded,
                        forwarded_to=forwarded_to, **kwargs)
        self.memory_ranges[address:address + size] = m
        return m

    def get_memory_range(self, address):
        """
        Get a memory range from an address
        Note: for now just get's one range. If there are multiple ranges
        at the same address, this method won't work (for now)

        :param address: the address of the range
        :returns:       the memory range
        """
        ranges = self.memory_ranges[address]
        if len(ranges) > 1:
            raise Exception("More than one memory range specified at 0x%x, \
                         not supported yet!" % address)
        elif len(ranges) == 0:
            raise Exception("No Memory range specified at 0x%x" %
                            address)
        return ranges.pop().data

    @watch('StateTransfer')
    def transfer_state(self, from_target, to_target,
                       sync_regs=True, synced_ranges=[]):
        """
        Transfers the state from one target to another one

        :param from_target:     the source target
        :param to_target:       the destination target
        :param sync_regs:      Whether registers should be synced
        :param synced_ranges:  The memory ranges whose contents should be
                                transfered
        :type from_target:      Target()
        :type to_target:        Target()
        :type sync_regs:       bool
        :type synced_ranges:   list
        """

        if from_target.state != TargetStates.STOPPED or \
                        to_target.state != TargetStates.STOPPED:
            raise Exception("Targets must be stopped for State Transfer, \
                             but target_states are (%s, %s)" %
                            (from_target.state, to_target.state))

        if sync_regs:
            # Test if we can take registers from TargetRegs-objects
            regs = (
                to_target.regs._get_names() & from_target.regs._get_names()
                if hasattr(to_target, 'regs') and hasattr(from_target, 'regs')
                else self.arch.registers)
           
            # The status register can cause a mode-switch, let's update it first
            if self.arch.sr_name in regs:
                regs = ([self.arch.sr_name]
                        + [r for r in regs if r != self.arch.sr_name] )

            # Sync the registers!
            for r in regs:
                to_target.write_register(r, from_target.read_register(r))
            self.log.info('Synchronized Registers')

        for range in synced_ranges:
            m = from_target.read_memory(range.address, 1, range.size, raw=True)
            to_target.write_memory(range.address, 1, m, raw=True)
            self.log.info('Synchronized Memory Range: %s' % range.name)

    @watch('UpdateState')
    def _handle_update_state_message(self, message):
        self.log.info("Received state update of target %s to %s" %
                      (message.origin.name, message.state))

    @watch('BreakpointHit')
    def _handle_breakpoint_hit_message(self, message):
        self.log.info("Breakpoint hit for Target: %s" % message.origin.name)
        self._handle_update_state_message(message)

    @watch('RemoteMemoryRead')
    def _handle_remote_memory_read_message(self, message):
        range = self.get_memory_range(message.address)

        if not range.forwarded:
            raise Exception("Forward request for non forwarded range received!")
        if range.forwarded_to is None:
            raise Exception("Forward request for non existing target received.\
                            (Address = 0x%x)" % message.address)

        try:
            mem = range.forwarded_to.read_memory(message.address, message.size)
            success = True
        except:
            mem = -1
            success = False
        message.origin.protocols.remote_memory.send_response(message.id, mem,
                                                             success)
        return (message.id, mem, success)

    @watch('RemoteMemoryWrite')
    def _handle_remote_memory_write_msg(self, message):
        mem_range = self.get_memory_range(message.address)
        if not mem_range.forwarded:
            raise Exception("Forward request for non forwarded range received!")
        if mem_range.forwarded_to is None:
            raise Exception("Forward request for non existing target received!")

        success = mem_range.forwarded_to.write_memory(message.address, message.size,
                                                      message.value)

        message.origin.protocols.remote_memory.send_response(message.id, 0,
                                                             success)
        return message.id, 0, success

    def run(self):
        """
        The code of the Thread managing the asynchronous messages received.
        Default behavior: wait for the priority queue to hold a message and call
        the _async_handler method to process it.
        """
        self._close.clear()
        while True:
            if self._close.is_set():
                break

            try:
                message = self.queue.get(timeout=0.5)
            except:
                continue
            self.log.debug("Avatar received %s" % message)

            handler = self.message_handlers.get(message.__class__, None)
            if handler is None:
                raise Exception("No handler for Avatar-message %s registered" %
                                message)
            else:
                handler(message)

    def stop(self):
        """
        Stop the thread which manages the asynchronous messages.
        """
        self._close.set()
        self.join()

    @watch('AvatarGetStatus')
    def get_status(self):
        return self.status

class AvatarFastQueueProcessor(Thread):
    """
    The avatar fast queue handles events which require immediate action, 
    i.e. TargetStateUpdates. 
    After processing, they get passed to the main avatar queue for further
    handling.
    """

    def __init__(self, avatar):
        super(AvatarFastQueueProcessor, self).__init__()
        self.avatar = avatar
        self._close = Event()
        self.daemon = True
        self.start()

    def run(self):
        self._close.clear()
        while True:
            if self._close.is_set():
                break

            try:
                message = self.avatar.fast_queue.get(timeout=0.1)
            except queue.Empty as e:
                continue

            if isinstance(message, UpdateStateMessage):
                message.origin.update_state(message.state)
                self.avatar.queue.put(message)
            else:
                raise Exception("Unknown Avatar Fast Message received")

    def stop(self):
        """
        Stop the thread which manages the asynchronous messages.
        """
        self._close.set()
        self.join()
