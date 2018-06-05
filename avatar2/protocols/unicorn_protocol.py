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
    def __init__(self, avatar, arch=ARM, origin=None):
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
        if self._alive:
            self._worker_queue.put((None, None))
            self.stop()
            self._worker.join()
            self._alive = False

    # Execution protocol

    def cont(self):
        pc = self._fixup_pc(self.read_register(self._arch.pc_name))
        self._worker_emu_start(pc, 0)  # TODO 0 could be a valid address

    def stop(self):
        self.uc.emu_stop()

    def step(self):
        pc = self._fixup_pc(self.read_register(self._arch.pc_name))
        self._worker_emu_start(pc, 0, count=1)  # TODO 0 could be a valid address

    def set_breakpoint(self, line, hardware=False, temporary=False, regex=False, condition=None,
                       ignore_count=0, thread=0):
        # TODO support args, line <-> addr
        # right now we use line as addr
        hook = self.uc.hook_add(unicorn.UC_HOOK_CODE, self._breakpoint_hook, begin=line, end=line)
        self._hooks.append([hook])
        return len(self._hooks) - 1

    def set_watchpoint(self, variable, write=True, read=False):
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
        for hook in self._hooks[bkptno]:
            self.uc.hook_del(hook)

    # Memory protocol

    def read_memory(self, address, wordsize=4, num_words=1, raw=False):
        raw_mem = self.uc.mem_read(address, wordsize * num_words)
        if raw:
            return raw_mem

        # TODO: endianness support
        num2fmt = {1: 'B', 2: 'H', 4: 'I', 8: 'Q'}
        fmt = '<{}{}'.format(num_words, num2fmt[wordsize])
        mem = struct.unpack(fmt, raw_mem)
        return mem[0] if num_words == 1 else mem

    def write_memory(self, address, wordsize, val, num_words=1, raw=False):
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
        self.uc.reg_write(self._arch.unicorn_registers[reg], value)

    def read_register(self, reg):
        return self.uc.reg_read(self._arch.unicorn_registers[reg])

    # Remote memory protocol

    def send_response(self, id, value, success):
        self._rmp_queue.put((value, success))
        return True

    # ---

    def _forward_hook(self, uc, access, address, size, value, user_data):
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
        self.stop()

    def _watchpoint_hook(self, access, address, size, value, user_data):
        self.stop()

    def _worker_emu_start(self, *args, **kwargs):
        self._worker_queue.put((args, kwargs))

    def _fixup_pc(self, pc):
        # TODO what if a thumb target is in ARM mode?
        return pc | 1 if self._arch.unicorn_mode == unicorn.UC_MODE_THUMB else pc


class UnicornWorker(Thread):
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
