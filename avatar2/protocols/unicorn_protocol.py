import sys
if sys.version_info < (3, 0):
    import Queue as queue
else:
    import queue

import struct
import unicorn
import logging

from threading import Thread
from collections import namedtuple

from avatar2.message import UpdateStateMessage, RemoteMemoryReadMessage, \
    RemoteMemoryWriteMessage, BreakpointHitMessage
from avatar2.targets import TargetStates
from avatar2.archs.arm import ARM


class UnicornBreakpoint(object):
    __slots__ = ('hooks', 'temporary', 'ignore_count')

    def __init__(self, hooks, temporary=False, ignore_count=0):
        self.hooks = hooks
        self.temporary = temporary
        self.ignore_count = ignore_count


UnicornWorkerEmuStartMessage = namedtuple('UnicornWorkerEmuStartMessage', ('single_step',))
UnicornWorkerUpdateStateMessage = namedtuple('UnicornWorkerUpdateStateMessage', ('state',))
UnicornWorkerBreakpointMessage = namedtuple('UnicornWorkerBreakpointMessage', ('bkptno', 'address'))


class UnicornProtocol(object):
    """Main class for the Unicorn protocol.

    :ivar uc:         the Unicorn instance
    :ivar log:        this protocol's logger
    :ivar arch:       this protocol's architecture
    :ivar pending_bp: set of pending breakpoint numbers
    """

    def __init__(self, avatar, arch=ARM, origin=None):
        """Construct the protocol, along with its Unicorn instance and worker.

        :param avatar: the Avatar object
        :param arch:   the architecture
        :param origin: the target utilizing this protocol
        """
        self.uc = unicorn.Uc(arch.unicorn_arch, arch.unicorn_mode)
        self.log = logging.getLogger((origin.log.name + '.' if origin is not None else '') +
                                     self.__class__.__name__)
        self.arch = arch
        self.pending_bp = set()
        self._avatar_queue = avatar.queue
        self._avatar_fast_queue = avatar.fast_queue
        self._origin = origin
        self._breakpoints = []
        self._rmp_queue = queue.Queue()
        self._alive = True

        for start, end, mr in avatar.memory_ranges:
            perms = unicorn.UC_PROT_NONE
            if 'r' in mr.permissions:
                perms |= unicorn.UC_PROT_READ
            if 'w' in mr.permissions:
                perms |= unicorn.UC_PROT_WRITE
            if 'x' in mr.permissions:
                perms |= unicorn.UC_PROT_EXEC

            self.uc.mem_map(start, end - start, perms=perms)

            if hasattr(mr, 'file') and mr.file is not None:
                with open(mr.file, 'rb') as data:
                    self.uc.mem_write(start, data.read())

            if mr.forwarded:
                self.uc.hook_add(unicorn.UC_HOOK_MEM_VALID, self._forward_hook,
                                 begin=start, end=end)

        self._avatar_fast_queue.put(UpdateStateMessage(self._origin, TargetStates.INITIALIZED))

        self._worker_queue = queue.Queue()
        self._worker_queue.put(UnicornWorkerUpdateStateMessage(TargetStates.STOPPED))

        self._worker = UnicornWorker(self._origin, self, self.uc, self._worker_queue,
                                     self._avatar_fast_queue)
        self._worker.start()

    def __del__(self):
        self.shutdown()

    def shutdown(self):
        """Shutdown the protocol."""
        if self._alive:
            self._worker_queue.put(None)
            self.stop()
            self._worker.join()
            self._alive = False

    # Execution protocol

    def cont(self):
        """Continue execution."""
        self._worker_emu_start()

    def stop(self):
        """Stop execution."""
        self._worker_emu_stop()

    def step(self):
        """Execute one instruction and stop."""
        self._worker_emu_start(single_step=True)

    def set_breakpoint(self, line, hardware=True, temporary=False, regex=False, condition=None,
                       ignore_count=0, thread=0):
        """Insert a breakpoint.

        :param line:         address to break at
        :param hardware:     whether this breakpoint is hardware (ignored, always True)
        :param temporary:    whether this breakpoint is temporary (one shot)
        :param regex:        not supported
        :param condition:    not supported
        :param ignore_count: amount of times the breakpoint should be ignored before firing
        :param thread:       not supported
        :return: breakpoint number
        """
        if not hardware:
            self.log.warning('Software breakpoints are not supported, falling back to hardware')
        if regex:
            self.log.warning('Regex breakpoints are not supported, ignoring regex')
        if condition is not None:
            self.log.warning('Conditional breakpoints are not supported, ignoring condition')
        if thread:
            self.log.warning('Thread-specific breakpoints are not supported, ignoring thread')
        # TODO line <-> addr
        bkptno = len(self._breakpoints)
        hook = self.uc.hook_add(unicorn.UC_HOOK_CODE, self._breakpoint_hook, begin=line,
                                end=line, user_data=bkptno)
        self._breakpoints.append(UnicornBreakpoint(hooks=[hook], temporary=temporary,
                                                   ignore_count=ignore_count))
        return bkptno

    def set_watchpoint(self, variable, write=True, read=False):
        """Insert a watchpoint.
        This is currently NOT WORKING because of a bug in Unicorn.
        See https://github.com/unicorn-engine/unicorn/issues/972 for further details.

        :param variable: address to watch
        :param write:    whether to watch writes
        :param read:     whether to watch reads
        :return: watchpoint number
        """
        # TODO variable <-> addr
        bkptno = len(self._breakpoints)
        hooks = []
        if write is True:
            hooks.append(self.uc.hook_add(unicorn.UC_HOOK_MEM_WRITE, self._watchpoint_hook,
                                          begin=variable, end=variable, user_data=bkptno))
        if read is True:
            hooks.append(self.uc.hook_add(unicorn.UC_HOOK_MEM_READ, self._watchpoint_hook,
                                          begin=variable, end=variable, user_data=bkptno))
        self._breakpoints.append(UnicornBreakpoint(hooks=hooks))
        return bkptno

    def remove_breakpoint(self, bkptno):
        """Remove a breakpoint or watchpoint.

        :param bkptno: breakpoint/watchpoint number
        """
        for hook in self._breakpoints[bkptno].hooks:
            self.uc.hook_del(hook)
        self._breakpoints[bkptno] = None

    # Memory protocol

    def read_memory(self, address, wordsize, num_words=1, raw=False):
        """Read memory.

        :param address:   the address to read from
        :param wordsize:  the size of a read word (1, 2, 4 or 8)
        :param num_words: the amount of words to read
        :param raw:       whether the read memory should be returned unprocessed
        :return: the read memory
        :rtype:  int if num_words == 1 and raw == False,
                 list of int if num_words > 1 and raw == False,
                 str or byte if raw == True
        """
        raw_mem = self.uc.mem_read(address, wordsize * num_words)
        if raw:
            return raw_mem

        # TODO: endianness support
        num2fmt = {1: 'B', 2: 'H', 4: 'I', 8: 'Q'}
        fmt = '<{}{}'.format(num_words, num2fmt[wordsize])
        mem = struct.unpack(fmt, raw_mem)
        return mem[0] if num_words == 1 else mem

    def write_memory(self, address, wordsize, val, num_words=1, raw=False):
        """Write memory.

        :param address:   the address to write to
        :param wordsize:  size of a written word (1, 2, 4 or 8)
        :param val:       the value to write
        :type val:        int if num_words == 1 and raw == False,
                          list of int if num_words > 1 and raw == False,
                          str or byte if raw == True
        :param num_words: the amount of words to write
        :param raw:       whether to write in raw mode
        :return: True on success, False otherwise
        """
        if raw:
            raw_mem = val
        else:
            # TODO: endianness support
            num2fmt = {1: 'B', 2: 'H', 4: 'I', 8: 'Q'}
            fmt = '<{}{}'.format(num_words, num2fmt[wordsize])
            if num_words == 1:
                raw_mem = struct.pack(fmt, val)
            else:
                raw_mem = struct.pack(fmt, *val)

        try:
            self.uc.mem_write(address, raw_mem)
            return True
        except unicorn.UcError:
            self.log.debug('Failed memory write @ 0x{:x}'.format(address))
            return False

    # Register protocol

    def write_register(self, reg, value):
        """Write a register.

        :param reg:   name of the register to write
        :param value: value to write
        """
        self.uc.reg_write(self.arch.unicorn_registers[reg], value)

    def read_register(self, reg):
        """Read a register.

        :param reg: name of the register to read
        :return: read value
        """
        return self.uc.reg_read(self.arch.unicorn_registers[reg])

    # Remote memory protocol

    def send_response(self, id, value, success):
        """Handle a remote memory response.

        :param id:      the request ID
        :param value:   read value, if it was a read request
        :param success: True if the request was successful, False otherwise
        :return: True if the response was handled successfully, False otherwise
        """
        self._rmp_queue.put((value, success))
        return True

    # ---

    def _forward_hook(self, uc, access, address, size, value, user_data):
        """Unicorn hook for memory forwarding."""
        pc = self.read_register(self.arch.pc_name)
        if access == unicorn.UC_MEM_READ or access == unicorn.UC_MEM_FETCH:
            msg = RemoteMemoryReadMessage(self._origin, 0, pc, address, size)
            write_back = True
        elif access == unicorn.UC_MEM_WRITE:
            msg = RemoteMemoryWriteMessage(self._origin, 0, pc, address, value, size)
            write_back = False
        else:
            raise ValueError('Forward hook with unknown access {}'.format(access))

        self._avatar_queue.put(msg)
        value, success = self._rmp_queue.get()
        if not success:
            self.log.debug('Remote memory request returned 0x{:x}'.format(value))
        elif write_back and not self.write_memory(address, size, value):
            self.log.debug('Failed to write back remote memory')

    def _breakpoint_hook(self, uc, address, size, bkptno):
        """Unicorn hook for breakpoints."""
        if bkptno in self.pending_bp:
            return
        bp = self._breakpoints[bkptno]
        if bp.ignore_count > 0:
            bp.ignore_count -= 1
            return

        self.pending_bp.add(bkptno)
        self._worker_queue.put(UnicornWorkerBreakpointMessage(bkptno, address))
        self.uc.emu_stop()

        if bp.temporary:
            self.remove_breakpoint(bkptno)

    def _watchpoint_hook(self, uc, access, address, size, value, bkptno):
        """Unicorn hook for watchpoints."""
        if bkptno in self.pending_bp:
            return
        self.pending_bp.add(bkptno)
        self.stop()

    def _worker_emu_start(self, single_step=False):
        """Start the emulation inside the worker."""
        self._worker_queue.put(UnicornWorkerEmuStartMessage(single_step))

    def _worker_emu_stop(self):
        """Stop the emulation inside the worker."""
        self._worker_queue.put(UnicornWorkerUpdateStateMessage(TargetStates.STOPPED))
        self.uc.emu_stop()


class UnicornWorker(Thread):
    """Worker class for the Unicorn protocol."""

    def __init__(self, origin, protocol, uc, worker_queue, avatar_queue):
        self._origin = origin
        self._protocol = protocol
        self._uc = uc
        self._worker_queue = worker_queue
        self._avatar_queue = avatar_queue
        super(UnicornWorker, self).__init__()

    def run(self):
        while True:
            msg = self._worker_queue.get()
            if msg is None:
                break
            if isinstance(msg, UnicornWorkerEmuStartMessage):
                self._avatar_queue.put(UpdateStateMessage(self._origin, TargetStates.RUNNING))
                if self._protocol.pending_bp:
                    # Single-step over pending breakpoints, the hook will ignore them
                    old_pending_bp = self._protocol.pending_bp.copy()
                    self._uc.emu_start(self._get_next_pc(), self._EMU_END_ADDRESS, count=1)
                    if self._protocol.pending_bp == old_pending_bp:
                        # We did not hit another breakpoint during the step, empty the pending set
                        self._protocol.pending_bp.clear()
                    if msg.single_step:
                        # We already stepped: done
                        continue
                if not self._protocol.pending_bp:
                    # Either there was no pending breakpoint, or we didn't hit
                    # another breakpoint while single stepping: keep running
                    count = 1 if msg.single_step else 0
                    self._uc.emu_start(self._get_next_pc(), self._EMU_END_ADDRESS, count=count)
            elif isinstance(msg, UnicornWorkerUpdateStateMessage):
                self._avatar_queue.put(UpdateStateMessage(self._origin, msg.state))
            elif isinstance(msg, UnicornWorkerBreakpointMessage):
                # When stopping from a hook, Unicorn resets the PC to the beginning of the basic
                # block that contains the instruction that triggered the hook.
                # The register state, however, isn't rolled back.
                # As a workaround, we set the PC here to the breakpoint address.
                # See https://github.com/unicorn-engine/unicorn/issues/969
                self._protocol.write_register(self._protocol.arch.pc_name, msg.address)
                self._avatar_queue.put(BreakpointHitMessage(self._origin, msg.bkptno, msg.address))
            else:
                raise Exception('Unknown message in Unicorn worker queue: {}'.format(msg))

    def _get_next_pc(self):
        """Get the PC to start emulation at."""
        pc = self._protocol.read_register(self._protocol.arch.pc_name)
        return self._fixup_thumb_pc(pc)

    def _fixup_thumb_pc(self, pc):
        """Fix the PC for emu_start to take ARM Thumb mode into account."""
        # If the arch mode is UC_MODE_THUMB, force Thumb.
        # Otherwise, check Thumb bit in CPSR.
        if self._protocol.arch.unicorn_arch == unicorn.UC_ARCH_ARM and \
                (self._protocol.arch.unicorn_mode == unicorn.UC_MODE_THUMB or
                 self._protocol.read_register(self._protocol.arch.sr_name) & 0x20):
            pc |= 1
        return pc

    _EMU_END_ADDRESS = 0  # TODO: 0 could be a valid address
