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
import json
import time

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

    def __init__(self, arch=ARM, cpu_model=None, output_directory=None,
                log_to_stdout=True):
        super(Avatar, self).__init__()

        self.shutdowned = False
        try:
            signal.signal(signal.SIGINT, self.sigint_wrapper)
            self.sigint_handler = self.shutdown
        except ValueError:
            # Cannot register SIGINT handler: we are not in main thread. Do not care about it.
            pass
        atexit.register(self.shutdown)

        self.watchmen = Watchmen(self)
        self.arch = arch
        self.arch.init(self)
        self.targets = {}
        self.status = {}
        self.memory_ranges = intervaltree.IntervalTree()
        self.loaded_plugins = []
        self.cpu_model = cpu_model

        if self.cpu_model is None and hasattr(self.arch, 'cpu_model'):
            self.cpu_model = self.arch.cpu_model
        # Setup output-dir and logging
        self.output_directory = (tempfile.mkdtemp(suffix="_avatar")
                                 if output_directory is None
                                 else output_directory)
        if not path.exists(self.output_directory):
            makedirs(self.output_directory)



        self.log = logging.getLogger('avatar')
        format = '%(asctime)s | %(name)s.%(levelname)s | %(message)s'

        logfile = '%s/avatar.log' % self.output_directory
        logging.basicConfig(filename=logfile,
                            level=logging.INFO, format=format,
                           )

        if log_to_stdout is True:
            handler = logging.StreamHandler(sys.stdout)
            handler.setFormatter(logging.Formatter(format))
            root = logging.getLogger()
            root.addHandler(handler)
        self.log.info("Initialized Avatar. Output directory is %s" %
                      self.output_directory)

        # Setup the avatarqueues and register default handler
        self._close = Event()
        self.queue = queue.Queue()
        self.fast_queue = queue.Queue()
        self.fast_queue_listener = AvatarFastQueueProcessor(self)
        self.message_handlers = {
            SyscallCatchedMessage: self._handle_syscall_catched_message,
            BreakpointHitMessage: self._handle_breakpoint_hit_message,
            UpdateStateMessage: self._handle_update_state_message,
            RemoteMemoryReadMessage: self._handle_remote_memory_read_message,
            RemoteMemoryWriteMessage: self._handle_remote_memory_write_message
        }
        self.daemon = True
        self.start()


    def load_config(self, file_name=None):
        """
        Populates the avatar object with targets and ranges saved in a config
        json. Note that some changes on the targets may be lost, for instance
        custom protocol configuration.
        :ivar file_name: (Absolute) path to the config file
        """
        if file_name is None:
            file_name = "%s/conf.json" % self.output_directory
        with open(file_name, 'r') as config_file:
            config = json.load(config_file)

        for t in config.pop('targets', []):
            module = __import__(t.pop('module'))
            klass = getattr(module, t.pop('type'))
            self.add_target(klass, **t)

        for mr in config.pop('memory_mapping', []):
            # resolve forwarded_to to the target objects
            tname = mr.get('forwarded_to')
            if tname is not None:
                if not tname in self.targets:
                    raise Exception(("Requested target %s not found in config. "
                                     "Aborting." % tname))
                mr['forwarded_to'] = self.targets[tname]
            # TODO handle emulate
            self.add_memory_range(mr.pop('address'),
                                  mr.pop('size'),
                                  **mr)
        for k, v in config.items():
            setattr(self, k, v)


    def generate_config(self):
        """
        Generates a configuration dictionary for storage based on the currently
        defined targets and memory ranges
        """
        conf_dict = {}
        if self.cpu_model is not None:
            conf_dict['cpu_model'] = self.cpu_model
        conf_dict['memory_mapping'] = []
        for mr in self.memory_ranges:
            conf_dict['memory_mapping'].append(mr.data.dictify())

        conf_dict['targets'] = []
        for t in self.targets.values():
            conf_dict['targets'].append(t.dictify())

        return conf_dict


    def save_config(self, file_name=None, config=None):
        if file_name is None:
            file_name = "%s/conf.json" % self.output_directory
        conf_dict = self.generate_config() if config is None else config
        with open(file_name, "w") as conf_file:
            json.dump(conf_dict, conf_file)


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

    def load_plugin(self, name, local=False):
        if local is True:
            plugin = __import__(name, fromlist=['.'])
        else:
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
                         forwarded=False, forwarded_to=None, emulate=None,
                         interval_tree=None, **kwargs):
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
        :param interval_tree:interval_tree this range shall be added to. If None,
                             the range will be added to self.memory_ranges
        """
        memory_ranges = self.memory_ranges if interval_tree is None else interval_tree
        if emulate:
            python_peripheral = emulate(name, address, size, **kwargs)
            forwarded = True
            forwarded_to = python_peripheral
            kwargs.update({'python_peripheral': python_peripheral})

        if forwarded is True:
            kwargs.update({'qemu_name': 'avatar-rmemory'})
        m = MemoryRange(address, size, name=name, permissions=permissions,
                        file=file, file_offset=file_offset,
                        file_bytes=file_bytes, forwarded=forwarded,
                        forwarded_to=forwarded_to, **kwargs)
        memory_ranges[address:address + size] = m
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
            self.log.critical("No Memory range specified at 0x%x" %
                            address)
            return None
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


            # ARM may have banked registers; Apparantly, the order in which we
            # write them is important to QEMU and could to lead bugs otherwise.
            if self.arch == ARM:
                regs = sorted(regs, key=lambda x: x[::-1])

            # The status register can cause a mode-switch, let's update it first
            if self.arch.sr_name in regs:
                regs = ([self.arch.sr_name]
                        + [r for r in regs if r != self.arch.sr_name] )

            # Sync the registers!
            for r in regs:
                val = from_target.read_register(r)
                to_target.write_register(r, val)
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
        # Breakpoints are two stages: SYNCING | STOPPED -> HandleBreakpoint -> STOPPED
        # This makes sure that all handlers are complete before stopping and breaking wait()

        def bp_end_sync_cb(avatar, message, *args, **kwargs):
                avatar.watchmen.remove_watchman('BreakpointHit', w)
                avatar.fast_queue.put(UpdateStateMessage(message.origin,
                                                         TargetStates.STOPPED))

        # We handle this via a watchmen added in here, so we are sure that this
        # watchmen gets executed *at the end*
        # Note: This can break if another breakpoint-hit callback inserts an
        #       additional breakpointhit-watchmen (after).
        w = self.watchmen.add('BreakpointHit', when='after',
                              callback=bp_end_sync_cb)


    @watch('SyscallCatched')
    def _handle_syscall_catched_message(self, message):
        self.log.info("Syscall catched for Target: %s" % message.origin.name)
        self._handle_update_state_message(message)


    @watch('RemoteMemoryRead')
    def _handle_remote_memory_read_message(self, message):

        range = self.get_memory_range(message.address)
        if not range:
            return (message.id, None, False)
        message.dst = range
        if not range.forwarded:
            raise Exception("Forward request for non forwarded range received!")
        if range.forwarded_to is None:
            raise Exception("Forward request for non existing target received.\
                            (Address = 0x%x)" % message.address)

        try:
            mem = range.forwarded_to.read_memory(message.address, message.size, message.num_words, message.raw)
            if not message.raw and message.num_words == 1 and not isinstance(mem, int):
                raise Exception(("Forwarded read returned data of type %s "
                                 "(expected: int)" % type(mem)))
            success = True
        except Exception as e:
            self.log.exception("RemoteMemoryRead failed: %s" % e)
            mem = -1
            success = False
        message.origin.protocols.remote_memory.send_response(message.id, mem,
                                                             success)
        return (message.id, mem, success)

    @watch('RemoteMemoryWrite')
    def _handle_remote_memory_write_message(self, message):
        mem_range = self.get_memory_range(message.address)
        if not mem_range:
            message.origin.protocols.remote_memory.send_response(message.id, 0, True)
            return (message.id, 0, False)
        message.dst = mem_range
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
                message = self.queue.get(timeout=0.1)
            except:
                continue
            self.log.debug("Avatar received %s. Queue-Status: %d/%d" % (message,
                            self.queue.qsize(), self.fast_queue.qsize()))

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
        self.message_handlers = {
            UpdateStateMessage: self._fast_handle_update_state_message,
            BreakpointHitMessage: self._fast_handle_update_state_message,
            SyscallCatchedMessage: self._fast_handle_update_state_message,
        }

        self.start()


    def _fast_handle_update_state_message(self, message):
        #print message
        message.origin.update_state(message.state)
        self.avatar.queue.put(message)



    def run(self):
        self._close.clear()
        while True:
            if self._close.is_set():
                break

            # get() blocks sometimes.  This is a non-blocking wait.
            #if self.avatar.fast_queue.empty():
                #time.sleep(.001)
                #continue

            try:
                message = self.avatar.fast_queue.get(timeout=0.1)
            except:
                continue

            handler = self.message_handlers.get(message.__class__, None)
            if handler is None:
                raise Exception("No handler for fast message %s registered" %
                                message)

            else:
                handler(message)

    def stop(self):
        """
        Stop the thread which manages the asynchronous messages.
        """
        self._close.set()
        self.join()
