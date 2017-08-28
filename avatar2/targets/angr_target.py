from threading import Event, Thread
from types import MethodType

from angr import sim_options as o


import logging
import Queue as queue

import angr
from angr.storage.paged_memory import BasePage, SimPagedMemory
from angr.storage.memory_object import SimMemoryObject


from angr.state_plugins.symbolic_memory import SimSymbolicMemory
from claripy import BVV

from avatar2.targets import Target, TargetStates
from avatar2.message import RemoteMemoryReadMessage, RemoteMemoryWriteMessage


class AvatarPage(BasePage):

    def __init__(self, *args, **kwargs):
        origin = kwargs.pop('origin', None)
        self.id = kwargs.pop('req_id', 0)

        super(self.__class__, self).__init__(*args, **kwargs)
        self.avatar = origin.avatar
        self.origin = origin

    def copy(self):
        return AvatarPage(self._page_addr, self._page_size,
                          permissions=self.permissions,
                          origin=self.origin, req_id=self.id)


    def store_mo(self, state, new_mo, overwrite=True): 
        #overwrite=True means that that it's a normal write, False means that the blank parts of the page are being filled in with default data
         # do your stuff

        address = new_mo.base
        value = state.se.any_int(new_mo.object)
        size = new_mo.size()/8 # Claripy uses bit- and not bytesizes

        #import IPython; IPython.embed()
        
        MemoryForwardMsg = RemoteMemoryWriteMessage(self.origin, self.id,
                                                    address, value, size)
        self.avatar.queue.put(MemoryForwardMsg)
        r_id, r_value, r_success = self.origin.response_queue.get()
        if self.id != r_id:
            raise("AvatarAngrMemory received mismatching id!")
        if r_success != True:
            raise Exception("AvatarAngrMemory remote memory request failed!")
         
         
        self.id += 1
        return r_success


    def load_slice(self, state, start, end):
        print "my load_slice"

        MemoryForwardMsg = RemoteMemoryReadMessage(self.origin, self.id, start,
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


#class SimAvatarState(SimState):


    #def __init__(self, origin=None, **kwargs):
        #options = set(kwargs.get('options', set()))
        #add_options = kwargs.get('add_options')
        #remove_options = kwargs.get('remove_options')

        #if add_options is not None:
            #options |= add_options
        #if remove_options is not None:
            #options -= remove_options

        #m_options = set([o.ABSTRACT_MEMORY, o.FAST_MEMORY])

    #if options & m_options:
        #l.warning('Discarding user-defined memory options for avatar state')
        #r_options = kwargs.get('remove_options',set())
        #kwargs['remove_options'] = r_options.update(m_options)

        #m_options = set([o.ABSTRACT_MEMORY, o.FAST_MEMORY])

        #if options & m_options:
            #l.warning('Discarding user-defined memory options for avatar state')
            #r_options = kwargs.get('remove_options',set())
            #kwargs['remove_options'] = r_options.update(m_options)


        #memory_storage = SimPagedMemory(page_size=4096)
        #sim_memory = SimSymbolicMemory(mem=memory_storage)

        #super(SimAvatarState, self).__init__(self, arch="AMD64", plugins=None, memory_backer=None, permissions_backer=None, mode=None, options=None,
                                                          #add_options=None, remove_options=None, special_memory_filler=None, os_name=None

                                            #)
        #if origin is None:
            #raise Exception(("SimAvatarState without Origin instantiated!"
                              #"Bailing out!"))
#class AvatarStatePlugin(SimStatePlugin):
    #'''This class enables an AvatarAPI to the SimState.
    #'''


def avatar_state(angr_factory, **kwargs):
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
  
    options = set(kwargs.get('options', set()))
    add_options = kwargs.get('add_options')
    remove_options = kwargs.get('remove_options')

    if add_options is not None:
        options |= add_options
    if remove_options is not None:
        options -= remove_options

    unsupported_options = set([o.ABSTRACT_MEMORY, o.FAST_MEMORY])

    if options & unsupported_options:
        l.warning('Discarding user-defined memory options for avatar state')
        r_options = kwargs.get('remove_options',set())
        kwargs['remove_options'] = r_options.update(m_options)

    permissions_backer = angr_factory._project.loader.memory 
    
    memory_backer = kwargs.get('memory_backer',
                               angr_factory._project.loader.memory)
    permissions_backer = generate_permissions_backer()
    page_size = angr_factory._project.loader.page_size

    #SimPagedMemory requires both pages and symbolic_addresses to be dicts
    #with the same keys
    pages = {}
    symbolic_addrs = {}
    for (start, end, mr) in angr_factory.origin.avatar.memory_ranges:
        if mr.forwarded:
            page_num = start / page_size
            while page_num * page_size < end:
                pages[page_num] = AvatarPage(start,
                                             page_size, 
                                             origin=angr_factory.origin)
                symbolic_addrs[page_num] = set()
                page_num += 1

    memory_storage = SimPagedMemory(page_size=page_size, pages=pages,
                                    symbolic_addrs=symbolic_addrs,
                                    check_permissions=True,
                                    memory_backer=memory_backer,
                                    permissions_backer=permissions_backer)


    sim_memory = SimSymbolicMemory(mem=memory_storage, memory_id='mem')

    plugins = kwargs.get('plugins',{})
    if plugins.has_key('memory'):
        l.warning('Discarding user-defined memory plugin for avatar state')
    plugins['memory'] = sim_memory

    kwargs['plugins'] = plugins

    avatar_state = angr_factory.blank_state(**kwargs)

    return avatar_state




class AngrTarget(Target):
    ''' The angr-target does not require additional protocols
    Reason for this is that the '''

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

        # If no base addr is specified, try to figure it out via memory ranges
        for (start, end, mr) in self.avatar.memory_ranges:
            if hasattr(mr, 'file') and mr.file == self.binary:
                self.base_addr = start

        load_options = {}
        load_options['main_opts'] = {'backend': 'blob', 
                                     'custom_arch': self.avatar.arch.angr_name,
                                     'custom_base_addr': self.base_addr,
                                     'custom_entry_point': self.base_addr,
                                    }
        load_options['auto_load_libs'] = False,
        load_options['page_size'] = 0x1000 # change me once angr is ready!

        print self.base_addr

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

        self.angr = angr.Project(self.binary, load_options=load_options)
        self.angr.factory.origin = self
        self.angr.factory.avatar_state = MethodType(avatar_state, self.angr.factory)


        self.base_state = self.angr.factory.avatar_state()
        # Now that we have an angr-project, let's load the other ranges
        self._remote_memory_protocol = self


        self._exec_protocol = None
        self._memory_protocol = self
        self._register_protocol = self
        self._signal_protocol = None
        self._monitor_protocol = None
        self.state = TargetStates.STOPPED

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
