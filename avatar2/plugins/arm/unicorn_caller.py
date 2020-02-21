from types import MethodType

#from keystone import *
from ...targets.unicorn_target import UnicornTarget
from intervaltree import IntervalTree

from unicorn import UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, UC_MEM_READ, UC_MEM_WRITE

def _callable_uc_mem_hook(self, uc, access, address, size, value, user_data):

    # Sync on access. However, we only syncronize pages which are not forwarded
    if self.avatar.get_memory_range(address).forwarded is False and \
       self._callable_synced_pages[address] == set():
        page = address - (address % 0x1000)
        content = self.read_memory( page, 0x1000, raw=True)
        uc.mem_write(page, content)
        self._callable_synced_pages[page:page+0x1000] = content

    if access == UC_MEM_WRITE:
        self._callable_writes.append((address, size, value)) 
        if self._callable_do_writes is True:
            self.write_memory(address, size, value)




def call(self, address, args=None, playground=0x10000000, do_writes=False):
    '''
    Calls the function at the given address with the current state of the program.
    Internally, this method creates a unicorn target

    :returns: a dictionary with changed memory locations and values.
    '''

    # Step1: Set up unicorn
    self._callable_writes = []
    self._callable_do_writes = True
    self._callable_synced_pages = IntervalTree()
    
    if hasattr(self, '_callable_unicorn'):
        unicorn = self._callable_unicorn
    else:
        unicorn = UnicornTarget(self.avatar)
        self._callable_unicorn = unicorn

    unicorn.init()
    unicorn.wait()

    unicorn.add_hook(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE,
                     self._callable_uc_mem_hook)
    unicorn.protocols.memory.uc.mem_map(playground, 0x1000)
    

    # Step2: Setup Unicorn State
    self.avatar.transfer_state(self, unicorn)
    unicorn.set_breakpoint(unicorn.regs.lr)

    # The following sets up the args in memory
    playground_pointer = playground
    for i in range(len(args)):
        if type(args[i]) == int:
            setattr(unicorn.regs, 'r%d' % i, args[i]) 
        unicorn.write_memory(playground_pointer, 1, args[i], raw=True)
        playground_pointer += len(args[i])


    # Step3: Do the emulation
    self.log.info("Starting Emulation of %x" % address)
    unicorn.regs.pc = address
    unicorn.cont()
    unicorn.wait()
    

    # Step4: Cleanup & Exit
    writes = self._callable_writes
    del(self._callable_writes)
    del(self._callable_do_writes)
    del(self._callable_synced_pages)

    return writes
    
    




def target_added_callback(avatar, *args, **kwargs):
    target = kwargs['watched_return']
    target.call = MethodType(call, target)
    target._callable_uc_mem_hook = MethodType(_callable_uc_mem_hook, target)


def load_plugin(avatar):
    avatar.watchmen.add_watchman('AddTarget', when='after',
                                 callback=target_added_callback)
    for target in avatar.targets.values():
        target.call = MethodType(call, target)
        target._callable_uc_mem_hook = MethodType(_callable_uc_mem_hook, target)
