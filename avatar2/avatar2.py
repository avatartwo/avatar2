import sys
if sys.version_info < (3, 0):
    import Queue as queue
else:
    import queue

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
from .targets.target import TargetStates
from .watchmen import Watchmen, BEFORE, AFTER, watch


class Avatar(Thread):
    """The Avatar-object is the main interface of avatar.
    Here we can set the different targets, and more

    :ivar arch:     architecture of all targets
    :ivar endness:  used endianness


    """

    def __init__(self, arch=ARM, endness='little', output_directory=None):
        super(Avatar, self).__init__()

        self.arch = arch
        self.endness = endness
        self.watchmen = Watchmen(self)
        self.targets = {}
        self.transitions = {}
        self.status = {}
        self.memory_ranges = intervaltree.IntervalTree()

        self.output_directory = (tempfile.mkdtemp(suffix="_avatar")
                                  if output_directory is None
                                  else output_directory)
        if not path.exists(self.output_directory):
                makedirs(self.output_directory)

        self._close = Event()
        self.queue = queue.Queue()
        self.start()

        self.log = logging.getLogger('avatar')
        format = '%(asctime)s | %(name)s.%(levelname)s | %(message)s'
        logging.basicConfig(filename='%s/avatar.log' % self.output_directory, 
                            level=logging.INFO, format=format)
        self.log.info("Initialized Avatar. Output directory is %s" % 
                      self.output_directory)

        signal.signal(signal.SIGINT, self.sigint_wrapper)
        self.sigint_handler = self.shutdown
        self.loaded_plugins = []


    def shutdown(self):
        """
        Shuts down all targets and Avatar. Should be called at end of script
        in order to cleanly exit all spawned processes and threads
        """
        for t in self.targets.values():
            if t.state == TargetStates.RUNNING:
                t.stop()
        for t in self.targets.values():
            t.shutdown()
        for range in self.memory_ranges:
            if isinstance(range.data.forwarded_to, AvatarPeripheral):
                range.data.forwarded_to.shutdown()

        self.stop()

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

    

    def add_memory_range(self, address, size, name='', permissions='rwx', 
                         file=None, forwarded=False, forwarded_to=None, 
                         emulate=None, **kwargs):
        """
        Adds a memory range to avatar

        :param address:      Base-Address of the Range
        :param size:         Size of the range
        :param file:         A file backing this range, if applicable
        :param forwarded:    Whether this range should be forwarded
        :param forwarded_to: If forwarded is true, specify the forwarding target
        """
        if emulate:
            python_peripheral = emulate(name, address, size, **kwargs)
            forwarded = True
            forwarded_to = python_peripheral
            kwargs.update({'python_peripheral': python_peripheral})

        if forwarded == True:
            kwargs.update({'qemu_name': 'avatar-rmemory'})
        m = MemoryRange(address, size, name=name, permissions=permissions, 
                        file=file, forwarded=forwarded, 
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
                       synch_regs=True, synched_ranges=[]):
        """
        Transfers the state from one target to another one

        :param from_target:     the source target
        :param to_target:       the destination target
        :param synch_regs:      Whether registers should be synched
        :param synched_ranges:  The memory ranges whose contents should be 
                                transfered
        :type from_target:      Target()
        :type to_target:        Target()
        :type synch_regs:       bool
        :type synched_ranges:   list
        """
        

        if from_target.state != TargetStates.STOPPED or \
           to_target.state != TargetStates.STOPPED:
            raise Exception("Targets must be stopped for State Transfer, \
                             but target_states are (%s, %s)" % 
                             (from_target.state, to_target.state))

        if synch_regs:
            for r in self.arch.registers:
                to_target.write_register(r, from_target.read_register(r))
            self.log.info('Synchronized Registers')

        for range in synched_ranges:
            m = from_target.read_memory(range.address, 1, range.size, raw=True)
            to_target.write_memory(range.address, 1, m, raw=True)
            self.log.info('Synchronized Memory Range: %s' % range.name)


    @watch('UpdateState')
    def _handle_updateStateMessage(self, message):
        self.log.info("Received state update of target %s to %s" % 
                       (message.origin.name, message.state))
        message.origin.update_state(message.state)

    @watch('BreakpointHit')
    def _handle_breakpointHitMessage(self, message):
        self.log.info("Breakpoint hit for Target: %s" % message.origin.name)
        message.origin.update_state(TargetStates.STOPPED)

    @watch('RemoteMemoryRead')
    def _handle_remote_memory_read_message(self, message):
        range = self.get_memory_range(message.address)

        if range.forwarded != True:
            raise Exception("Forward request for non forwarded range received!")
        if range.forwarded_to == None:
            raise Exception("Forward request for non existing target received.\
                            (Address = 0x%x)" % message.address)

        
        try:
            mem = range.forwarded_to.read_memory(message.address, message.size)
            success = True
        except:
            mem = -1
            success = False
        message.origin._remote_memory_protocol.send_response(message.id, mem,
                                                             success)
        return (message.id, mem, success)

    @watch('RemoteMemoryWrite')
    def _handle_remote_memory_write_msg(self, message):
        range = self.get_memory_range(message.address)
        if range.forwarded != True:
            raise Exception("Forward request for non forwarded range received!")
        if range.forwarded_to == None:
            raise Exception("Forward request for non existing target received!")

        success = range.forwarded_to.write_memory(message.address, message.size,
                                                  message.value)

        message.origin._remote_memory_protocol.send_response(message.id, 0,
                                                             success)
        return (message.id, 0, success)

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

            message = None
            try:
                message = self.queue.get(timeout=0.5)
            except:
                continue
            self.log.debug("Avatar received %s" % message)

            if isinstance(message, UpdateStateMessage):
                self._handle_updateStateMessage(message)
            elif isinstance(message, BreakpointHitMessage):
                self._handle_breakpointHitMessage(message)
            elif isinstance(message, RemoteMemoryReadMessage):
                self._handle_remote_memory_read_message(message)
            elif isinstance(message, RemoteMemoryWriteMessage):
                self._handle_remote_memory_write_msg(message)
            else:
                raise Exception("Unknown Avatar Message received")



    def stop(self):
        """
        Stop the thread which manages the asynchronous messages.
        """
        self._close.set()
        self.join()

    @watch('AvatarGetStatus')
    def get_status(self):
        return self.status


