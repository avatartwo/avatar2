from threading import Event, Thread
from types import MethodType

from angr import sim_options as o
from cle import Clemory

import logging
import Queue as queue

import angr
from angr.storage.paged_memory import Page, SimPagedMemory, TreePage
from angr.storage.memory_object import SimMemoryObject
from angr.procedures import SIM_PROCEDURES as simprocedures

from angr.state_plugins.symbolic_memory import SimSymbolicMemory
from claripy import BVV

from avatar2.targets import Target, TargetStates, GDBTarget
from avatar2.message import RemoteMemoryReadMessage, RemoteMemoryWriteMessage

class AvatarPage(TreePage):
    '''
    Avatar-specific page with angr semantic.
    Based in TreePage because the default Page (ListPage) in angr allocates
    an object for each memory location, even if this location is not used at
    all.
    AvatarPage implements a copy-on-access mechanism to pull data from the
    remote target when a memory access occours. The entire page is collected
    to leverage locality of reference.
    '''
    cnt = 0
    def __init__(self, start, size, origin=None, req_id=0, cowed=False,
                 *args, **kwargs):
        super(self.__class__, self).__init__(page_addr=start,
                                             page_size=size,
                                             *args, **kwargs)
        self.id = req_id
        self.cowed = cowed
        self.avatar = origin.avatar
        self.origin = origin
        self.log = logging.getLogger('%s.%s' %
                                     (origin.log.name, self.__class__.__name__)
                                     ) if origin else \
            logging.getLogger(self.__class__.__name__)


    def copy(self):
        self.log.debug("AvatarPage at %x is being copied" % self._page_addr)
        return AvatarPage(self._page_addr, self._page_size,
                          **self._copy_args())

    def _copy_args(self):
        ret = super(self.__class__, self)._copy_args()
        ret['origin'] = self.origin
        ret['req_id'] = self.id
        ret['cowed'] = self.cowed
        return ret

    def fill_page_from_remote(self, state):
        AvatarPage.cnt += 1
        self.log.debug("Loading page at %x from remote" % self._page_addr)
        start_addr = self._page_addr
        end_addr = self._page_addr + self._page_size
        for x in xrange(start_addr, end_addr, state.arch.bytes):
            start, value = self._read_memory(state, x,
                                             x+state.arch.bytes)[0]
            value._object = value.object.reversed
            super(self.__class__, self).store_mo(state, value, overwrite=True)

    def store_mo(self, state, new_mo, overwrite=True):
        if self.cowed:
            return super(self.__class__, self).store_mo(state, new_mo,
                                                        overwrite)
        self.fill_page_from_remote(state)
        self.cowed = True
        super(self.__class__, self).store_mo(state, new_mo, overwrite)

    def load_mo(self, state, page_idx):
        self.log.debug("Reading")
        if self.cowed:
            return super(self.__class__, self).load_mo(state, page_idx)
        self.cowed = True
        self.fill_page_from_remote(state)
        return super(self.__class__, self).load_mo(state, page_idx)

    def load_slice(self, state, start, end):
        self.log.debug("Reading %x %x" % (start, end))
        if self.cowed:
            return super(self.__class__, self).load_slice(state, start, end)
        self.cowed = True
        self.fill_page_from_remote(state)
        return super(self.__class__, self).load_slice(state, start, end)


    def _read_memory(self, state, start, end):
        MemoryForwardMsg = RemoteMemoryReadMessage(self.origin, self.id,
                                                   0x0, # Fake PC
                                                   start,
                                                   end - start)
        self.avatar.queue.put(MemoryForwardMsg)

        r_id, r_value, r_success = self.origin.response_queue.get()

        if self.id != r_id:
            raise("AvatarAngrMemory received mismatching id!")
        if r_success != True:
            raise Exception("AvatarAngrMemory remote memory request failed!")

        self.id += 1
        # do your stuff
        return [(start, SimMemoryObject(BVV(r_value, (end-start)*8), start))]



def avatar_state(angr_factory, angr_target, options=frozenset(),
                 add_options=None, remove_options=None,
                 memory_backer=None, plugins=None,
                 load_register_from=None, **kwargs):
    '''
    This method sets up a SimState which is usable for avatar and will be
    registered to the project's factory.
    Currently, setting up an avatar-state consists of four phases:
        1) verifying that the state options dont include unsupported memory
           options. (AvatarStates only work on SimSymbolicMemory for now)
        2) Setting up the memory plugin of the state
        3) Creating the avatar plugin for the state
        4) Creating the actual state
    '''

    def generate_permissions_backer():
        return None

    l = logging.getLogger('angr.factory')
  
    options = set(options)
    unsupported_options = set([o.ABSTRACT_MEMORY, o.FAST_MEMORY])

    if options & unsupported_options:
        l.warning('Discarding user-defined memory options for avatar state')
        remove_options |= (options & unsupported_options)

    if add_options is not None:
        options |= add_options
    if remove_options is not None:
        options -= remove_options

    permissions_backer = angr_factory._project.loader.memory 
    
    if memory_backer is None:
        memory_backer = angr_factory._project.loader.memory

    permissions_backer = generate_permissions_backer()
    page_size = angr_factory._project.loader.page_size

    #SimPagedMemory requires both pages and symbolic_addresses to be dicts
    #with the same keys
    pages = {}
    symbolic_addrs = {}
    for (start, end, mr) in angr_factory.origin.avatar.memory_ranges:
        if not start % page_size == 0:
            log.warning("Memory ranges starts at addres %x which is not" +
                        " page aligned (page size: %x)" % (start, page_size))
        if not end % page_size == 0:
            log.warning("Memory ranges ends at addres %x which is not" +
                        " page aligned (page size: %x)" % (end, page_size))
        if mr.forwarded:
            page_num = start / page_size
            while page_num * page_size <= end:
                pages[page_num] = AvatarPage(page_num * page_size,
                                                    page_size, 
                                                    origin=angr_factory.origin)
                symbolic_addrs[page_num] = set()
                page_num += 1
    memory_storage = SimPagedMemory(page_size=page_size, pages=pages,
                                    symbolic_addrs=symbolic_addrs,
                                    check_permissions=True,
                                    memory_backer=memory_backer,
                                    permissions_backer=permissions_backer)


    sim_memory = SimSymbolicMemory(mem=memory_storage, memory_id='mem',
                                   check_permissions=True)

    if plugins is None:
        plugins = {}

    if plugins.has_key('memory'):
        l.warning('Discarding user-defined memory plugin for avatar state')
    plugins['memory'] = sim_memory

    avatar_state = angr_factory.blank_state(options=options,
                                            add_options=add_options,
                                            remove_options=remove_options,
                                            memory_backer=memory_backer,
                                            plugins=plugins, **kwargs)

    if load_register_from is not None:
        for reg in angr_target.avatar.arch.registers.keys():
            try:
                value = BVV(load_register_from.rr(reg),
                            avatar_state.arch.bits)
                avatar_state.registers.store(reg, value)
            except KeyError as e:
                l.warning("Register %s was not set." % str(e))
        avatar_state.scratch.ins_addr = avatar_state.regs.ip
        avatar_state.scratch.bbl_addr = avatar_state.regs.ip
        avatar_state.scratch.stmt_idx = 0

    avatar_state.history.jumpkind = 'Ijk_Boring'
    return avatar_state


class AngrRemoteMemoryListener():
    def __init__(self, target):
        self._target = target

    def send_response(self, id, value, success):
        self._target.response_queue.put((id, value, success))

    def shutdown(self):
        pass


class AngrTarget(Target):
    '''
    The angr-target is somewhat different from the other targets in avatar2,
    which usually communicate with something outside the bounder of the
    analysis process. Conversely, the angr target manages python objects which
    reside in the same process of the analysis script.
    '''

    def __init__(self, avatar, binary=None, base_addr=None, load_options=None,
                 entry_address=0x00, **kwargs):

        super(AngrTarget, self).__init__(avatar, **kwargs)
        self.binary = binary
        self.base_addr = base_addr
        self.breakpoints = {}
        self.load_options = load_options if load_options else {}
        self.entry_address = entry_address

        self.response_queue = queue.Queue()


    def init(self):
        prot = AngrRemoteMemoryListener(self)
        self.protocols.remote_memory = prot

        # If no base addr is specified, try to figure it out via memory ranges
        for (start, end, mr) in self.avatar.memory_ranges:
            if hasattr(mr, 'file') and mr.file == self.binary:
                self.base_addr = start

        ## Custom load_options for the angr Project. These are meant to enable
        ## angr to deal with binaries extracted from the memory of a process
        load_options = {}
        load_options['main_opts'] = {'backend': 'blob', 
                                     'custom_arch': self.avatar.arch.angr_name,
                                     'custom_base_addr': self.base_addr,
                                     'custom_entry_point': self.base_addr,
                                    }
        load_options['auto_load_libs'] = False,
        load_options['page_size'] = 0x1000 # change me once angr is ready!

        # Angr needs a "main-binary" to execute. If the user did not specify
        # one, we will create one on the fly based on avatar's memory_ranges
        if self.binary is None:
            filename = '{}/{}_memory.bin'.format(self.avatar.output_directory,
                                                 self.name)
            segments = []
            offset = 0
            with open(filename, 'wb') as mem_file:
                for (start, end, mr) in self.avatar.memory_ranges:
                    if mr.file is not None:
                        with open(mr.file, 'rb') as mr_file:
                            data = mr_file.read()
                            mem_file.write(data)
                            segments.append((offset, mr.address, len(data)))
                            offset += len(data)

            load_options['main_opts'].update({'segments': segments})
            self.binary = filename

        # Before loading the project, let's apply the user defined load_options
        load_options.update(self.load_options)

        ## Create the angr Project
        self.angr = angr.Project(self.binary, load_options=load_options)
        self.angr.factory.origin = self

        ## Add the capability to create angr state to the angr target
        self.angr.factory.avatar_state = MethodType(avatar_state,
                                                    self.angr.factory)

        # Now that we have an angr-project, let's load the other ranges
        self._remote_memory_protocol = self


        self._exec_protocol = None
        self._memory_protocol = self
        self._register_protocol = self
        self._signal_protocol = None
        self._monitor_protocol = None
        self.state = TargetStates.STOPPED


    def hook_symbols(self, from_target):
        '''
        Automatically hook all the functions that angr is able to emulate.
        First retreive the address of the symbols from the from_target
        and then hook this address with the corresponding angr SimProcedure.
        '''
        libraries = ['libc', 'glibc', 'linux_loader', 'posix',
                     'linux_kernel']
        sim_libraries = [simprocedures[lib] for lib in libraries]
        for lib in sim_libraries:
            for symbol in lib.items():
                prot = from_target.protocols.execution
                exists, addr = prot.get_symbol(symbol[0])
                if exists:
                    self.log.debug("Hooking the symbol %s" % symbol[0])
                    self.angr.hook(addr, symbol[1])

    def send_response(self, id, value, success):
        self.response_queue.put((id, value, success))

    def cont(self):
        pass


    def stop(self):
        pass

    def step(self):
        pass


    def write_memory(self, address, size, value, num_words=1, raw=False):
        pass


    def read_memory(self, address, size, words=1, raw=False):
        mem = []
        for i in range(words):
            word = self.base_state.memory.load(address+i*size, size)
            if raw == False:
                word =  self.base_state.se.any_int(word)
            mem.append(word)

        if words == 1:
            mem = mem[0]

        return mem        



    def write_register(self, register, value):
        setattr(self.base_state.regs, register, value)


    def read_register(self, register):
        reg_concrete = self.base_state.se.any_int( getattr(self.base_state.regs,
                                                           register)
                                                 )
        return reg_concrete

    def set_breakpoint(self, line, hardware=False, temporary=False, regex=False,
                       condition=None, ignore_count=0, thread=0):
        pass


    def remove_breakpoint(self, bkptno):
        pass

    def set_watchpoint(self, variable, write=True, read=False):
        raise("Watchpoints are not implemented for the angr target! :(")

'''
class SimAvatarMemory(SimPagedMemory):
    def __init__(self, **kwargs):
        super(SimAvatarMemory, self).__init__(**kwargs)



class AvatarAngrExplorer(Thread):
    """
    Targets in Avatar are designed to execute in parallel to the mainthread,
    hence, we use angrs explore in a seperated thread
    """

    def __init__(self, avatar, path_group, break_points):
        super(AvatarAngrExploir, self).__init__()
        self._close = Event()

    def run(self):
        while True:
            self._closed.set()

    def stop(self):
        """Stops the listening thread. Useful for teardown of the target"""
        self._close.set()
        self._closed.wait()
'''
