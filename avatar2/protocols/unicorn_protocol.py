import sys
if sys.version_info < (3, 0):
    import Queue as queue
else:
    import queue

import struct
import unicorn
import logging

from threading import Thread

from avatar2.message import UpdateStateMessage, RemoteMemoryReadMessage, RemoteMemoryWriteMessage
from avatar2.targets import TargetStates
from avatar2.archs.arm import ARM


class UnicornProtocol(object):
    """Main class for the Unicorn protocol.

    :ivar uc:  the Unicorn instance
    :ivar log: this protocol's logger
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
        self._avatar_queue = avatar.queue
        self._avatar_fast_queue = avatar.fast_queue
        self._arch = arch
        self._origin = origin
        self._hooks = []
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
        self._worker = UnicornWorker(self._origin, self.uc, self._worker_queue,
                                     self._avatar_fast_queue)
        self._worker.start()

    def __del__(self):
        self.shutdown()

    def shutdown(self):
        """Shutdown the protocol."""
        if self._alive:
            self._worker_queue.put((None, None))
            self.stop()
            self._worker.join()
            self._alive = False

    # Execution protocol

    def cont(self):
        """Continue execution."""
        pc = self._fixup_thumb_pc(self.read_register(self._arch.pc_name))
        self._worker_emu_start(pc, 0)  # TODO 0 could be a valid address

    def stop(self):
        """Stop execution."""
        self.uc.emu_stop()

    def step(self):
        """Execute one instruction and stop."""
        pc = self._fixup_thumb_pc(self.read_register(self._arch.pc_name))
        self._worker_emu_start(pc, 0, count=1)  # TODO 0 could be a valid address

    def set_breakpoint(self, line, hardware=False, temporary=False, regex=False, condition=None,
                       ignore_count=0, thread=0):
        """Insert a breakpoint.

        :param line:         address to break at
        :param hardware:     ignored
        :param temporary:    ignored
        :param regex:        ignored
        :param condition:    ignored
        :param ignore_count: ignored
        :param thread:       ignored
        :return: breakpoint number
        """
        # TODO support more kwargs, warn for others
        # TODO line <-> addr
        hook = self.uc.hook_add(unicorn.UC_HOOK_CODE, self._breakpoint_hook, begin=line, end=line)
        self._hooks.append([hook])
        return len(self._hooks) - 1

    def set_watchpoint(self, variable, write=True, read=False):
        """Insert a watchpoint.

        :param variable: address to watch
        :param write:    whether to watch writes
        :param read:     whether to watch reads
        :return: watchpoint number
        """
        # TODO variable <-> addr
        hooks = []
        if write is True:
            hooks.append(self.uc.hook_add(unicorn.UC_HOOK_MEM_WRITE, self._watchpoint_hook,
                                    begin=variable, end=variable))
        if read is True:
            hooks.append(self.uc.hook_add(unicorn.UC_HOOK_MEM_READ, self._watchpoint_hook,
                                     begin=variable, end=variable))
        self._hooks.append(hooks)
        return len(self._hooks) - 1

    def remove_breakpoint(self, bkptno):
        """Remove a breakpoint or watchpoint.

        :param bkptno: breakpoint/watchpoint number
        """
        for hook in self._hooks[bkptno]:
            self.uc.hook_del(hook)

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
        self.uc.reg_write(self._arch.unicorn_registers[reg], value)

    def read_register(self, reg):
        """Read a register.

        :param reg: name of the register to read
        :return: read value
        """
        return self.uc.reg_read(self._arch.unicorn_registers[reg])

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
        pc = self.read_register(self._arch.pc_name)
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

    def _breakpoint_hook(self, address, size, user_data):
        """Unicorn hook for breakpoints."""
        self.stop()

    def _watchpoint_hook(self, access, address, size, value, user_data):
        """Unicorn hook for watchpoints."""
        self.stop()

    def _worker_emu_start(self, *args, **kwargs):
        """Start the emulation inside the worker."""
        self._worker_queue.put((args, kwargs))

    def _fixup_thumb_pc(self, pc):
        """Fix the PC for emu_start to take ARM Thumb mode into account."""
        # If the arch mode is UC_MODE_THUMB, force Thumb.
        # Otherwise, check Thumb bit in CPSR.
        if self._arch.unicorn_arch == unicorn.UC_ARCH_ARM and \
                (self._arch.unicorn_mode == unicorn.UC_MODE_THUMB or
                 self.read_register(self._arch.sr_name) & 0x20):
            pc |= 1
        return pc


class UnicornWorker(Thread):
    """Worker class for the Unicorn protocol."""

    def __init__(self, origin, uc, worker_queue, avatar_queue):
        self._origin = origin
        self._uc = uc
        self._worker_queue = worker_queue
        self._avatar_queue = avatar_queue
        super(UnicornWorker, self).__init__()

    def run(self):
        self._avatar_queue.put(UpdateStateMessage(self._origin, TargetStates.STOPPED))
        while True:
            args, kwargs = self._worker_queue.get()
            if args is None:
                break
            self._avatar_queue.put(UpdateStateMessage(self._origin, TargetStates.RUNNING))
            self._uc.emu_start(*args, **kwargs)
            self._avatar_queue.put(UpdateStateMessage(self._origin, TargetStates.STOPPED))
