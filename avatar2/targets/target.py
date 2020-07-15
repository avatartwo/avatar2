import logging
import time
from sys import version_info
from functools import wraps
from threading import Event
from types import MethodType

from enum import IntEnum

from ..watchmen import watch


def action_valid_decorator_factory(state, protocol):
    """
    This decorator factory  is used to generate decorators which  verify that
    requested actions on a target, such as step(), stop(), read_register(), 
    write_register() and so on are actually executable.

    :param state: A mask specifying the required state of the Target
    :type state:  An entry of the Enum TargetStates
    :param protocol: The protocol required to execute the action.
    :type protocol: str
    """

    def decorator(func):
        @wraps(func)
        def check(self, *args, **kwargs):
            if getattr(self.protocols, protocol) is None:
                raise Exception(
                    "%s() requested but %s is undefined." %
                    (func.__name__, protocol))
            if not self.state.value & state.value:
                raise Exception("%s() requested but Target is %s" %
                                (func.__name__, TargetStates(self.state).name))
            return func(self, *args, **kwargs)

        return check

    return decorator

def synchronize_state(*states, **kwargs):
    """
    This decorator can be used to make sure that the target executed a desired
    set of state transitions in an particular order.
    This is useful, when the user explicitly requests the target to change
    it's state and need an update notification on the transition itself.
    Internally, this works by creating an event and using a watchmen to check
    whether it was triggered.
    :param *states: The desired states of the target
    :param transition_optional: Also allow to return if the target is already
                                in the desired states, even if the transition
                                didn't happen
    """
    def decorator(func):
        @wraps(func)
        def state_synchronizer(self, *args, **kwargs):
            state = states[-1]
            transition_optional = kwargs.get('transition_optional', False)

            blocking = kwargs.get('blocking', True)
            avatar = self.avatar
            if blocking is True:
                state_reached = Event()

                def state_synchronize_cb(avatar, message, *args, **kwargs):
                    if message.origin == self:
                        if message.state == state:
                            state_reached.set()
                            avatar.watchmen.remove_watchman('UpdateState', w)
                        elif message.state == TargetStates.EXITED:
                            raise Exception("Target %s exited" % self.name)

                w = avatar.watchmen.add('UpdateState', when='after',
                                        callback=state_synchronize_cb)
            if len(states) == 1:
                ret = func(self, *args, **kwargs)
            else:
                ret = synchronize_state(*states[:-1])(func)(self, *args, **kwargs)
            if blocking is True:
                if not (transition_optional == True and self.state == state):
                    state_reached.wait()
            return ret

        return state_synchronizer

    return decorator


class TargetStates(IntEnum):
    """
    A simple Enum for the different states a target can be in.
    """
    CREATED = 0x1
    INITIALIZED = 0x2
    STOPPED = 0x4
    RUNNING = 0x8
    SYNCING = 0x10
    EXITED = 0x20
    NOT_RUNNING = INITIALIZED | STOPPED
    BREAKPOINT = SYNCING | STOPPED

class TargetRegs(object):
    def __init__(self, target, register_dict):
        self._target = target
        self.__dict__.update(register_dict)

    def __getattribute__(self, name):
        if name == '_get_names' or name == '__dict__':
            return super(TargetRegs, self).__getattribute__(name)
        elif name in self._get_names():
            return self._target.read_register(name)
        else:
            return super(TargetRegs, self).__getattribute__(name)

    def __setattr__(self, name, value):
        if name == '_target':
            return super(TargetRegs, self).__setattr__(name, value)
        elif name in self._get_names():
            return self._target.write_register(name, value)
        else:
            return super(TargetRegs, self).__setattr__(name, value)

    def _update(self, reg_dict):
        self.__dict__.update(reg_dict)

    def _get_nr_from_name(self, reg_name):
        return self.__dict__[reg_name]

    def _get_names(self):
        names = set(self.__dict__) ^ set(['_target'])
        return names

class TargetProtocolStore(object):
    """This class stores the various protocols associated to one target"""

    DEFAULT_PROTOCOLS = ['memory', 'registers', 'execution']

    def __init__(self, additional_protocols=None):
        self.protocols = set(TargetProtocolStore.DEFAULT_PROTOCOLS)
        self.protocols |= additional_protocols if additional_protocols else set()
        self.unique_protocols = {} #Stores protocol references and their count
        for p in self.protocols:
            setattr(self, p, None)

    def set_all(self, instance, only_defaults=False):
        """
        Sets an instantiated protocol object for either all protocols in this
        store, or only the default ones
        :param instance: the protocol instance
        """
        protocols = (TargetProtocolStore.DEFAULT_PROTOCOLS if only_defaults
                     else self.protocols
                    )
        for p in protocols:
            setattr(self, p, instance)

    def shutdown(self):
        """Shutsdown all the associated protocols"""
        for p in self.protocols:
            #print("Unloading %s" % str(p))
            setattr(self, p, None)

    def __setattr__(self, name, value):
        if name == 'protocols' or name == 'unique_protocols':
            return super(TargetProtocolStore, self).__setattr__(name, value)

        # Check whether the protocol is already an attribute
        if hasattr(self, name) is False:
            self.protocols.add(name)
            saved_val = None
        else:
            saved_val = getattr(self, name)

        if value is not None and self.unique_protocols.get(value, None) is None:
            self.unique_protocols[value] = 0

        if value is None and saved_val is not None:
            self.unique_protocols[saved_val] -= 1
        elif value is not None and saved_val is None:
            self.unique_protocols[value] += 1
        elif value is not None and saved_val is not None:
            self.unique_protocols[value] += 1
            self.unique_protocols[saved_val] -= 1
     
        # if there is no reference left, let's shut the prot down
        if saved_val is not None and self.unique_protocols[saved_val] == 0:
            getattr(self, name).shutdown()

        return super(TargetProtocolStore, self).__setattr__(name, value)



class Target(object):
    """The Target object is one of Avatars core concept, as Avatar orchestrate 
    different targets.
    While the generic target has no implementation, it provides an insight over 
    all the functions a Target MUST implement
    """

    def __init__(self, avatar, name=None):  # type: ('Avatar', str) -> None
        """
        Creates a new instance of a Target.
        :param avatar: The avatar instance this target should be orchestrated by
        :param name: The name of this target, mainly for logging. This is optional and will be autogenerated otherwise.
        """
        super(Target, self).__init__()
        self.state = TargetStates.CREATED

        self.avatar = avatar
        self.name = name if name else self._get_unique_name()

        self.status = {}
        self._arch = avatar.arch
        self.protocols = TargetProtocolStore()

        self.state = TargetStates.CREATED

        self.log = logging.getLogger('%s.targets.%s' % (avatar.log.name, self.name))
        log_file = logging.FileHandler('%s/%s.log' % (avatar.output_directory, self.name))
        formatter = logging.Formatter('%(asctime)s | %(name)s.%(levelname)s | %(message)s')
        log_file.setFormatter(formatter)
        self.log.addHandler(log_file)

        self.regs = TargetRegs(self, self._arch.registers)

    def dictify(self):
        """
        Returns the memory range as *printable* dictionary for the config
        """

        ignore = ['state', 'status', 'regs', 'protocols', 'log', 'avatar']
        ignored_types = (MethodType)
        expected_types = (str, bool, int, list) 
        if version_info < (3, 0): expected_types += (unicode, )

        t_dict = {'type': self.__class__.__name__,
                  'module': self.__module__}

        for k, v in self.__dict__.items():
            if k in ignore: continue
            if k.startswith('_'): continue
            if v is None: continue
            if isinstance(v, ignored_types): continue
            if not isinstance(v, expected_types):
                raise Exception(
                    "Unsupported type %s for dictifying %s for target %s" %
                    (type(v), k, self.name))
            t_dict[k] = v
        return t_dict



    @watch('TargetInit')
    def init(self):
        """
        Initializes the target to start the analyses
        """
        pass

    @watch('TargetShutdown')
    def shutdown(self):
        """
        Shutdowns the target
        """
        self.protocols.shutdown()

    @watch('TargetCont')
    @action_valid_decorator_factory(TargetStates.STOPPED, 'execution')
    @synchronize_state(TargetStates.RUNNING)
    def cont(self, blocking=True):
        """
        Continues the execution of the target
        :param blocking: if True, block until the target is RUNNING
        """
        return self.protocols.execution.cont()


    @watch('TargetStop')
    @action_valid_decorator_factory(TargetStates.RUNNING, 'execution')
    @synchronize_state(TargetStates.STOPPED, transition_optional=True)
    def stop(self, blocking=True):
        return self.protocols.execution.stop()

    @watch('TargetStep')
    @action_valid_decorator_factory(TargetStates.STOPPED, 'execution')
    @synchronize_state(TargetStates.RUNNING, TargetStates.STOPPED)
    def step(self, blocking=True):
        """
        Steps one instruction.
        :param blocking: if True, block until the target is STOPPED again
        """
        return self.protocols.execution.step()

    @watch('TargetSetFile')
    @action_valid_decorator_factory(TargetStates.STOPPED, 'execution')
    def set_file(self, elf):
        """
        Load an ELF file

        :param elf: ELF file to load
        :returns: True on success else False
        """
        if not hasattr(self.protocols.execution, 'set_file'):
            self.log.error('Protocol "' + type(self.protocols.execution).__name__ + '" does not support "set_file"')
            return False

        return self.protocols.execution.set_file(elf)

    @watch('TargetDownload')
    @action_valid_decorator_factory(TargetStates.STOPPED, 'execution')
    def download(self):
        """
        Download the loaded code to the Target

        :returns: True on success else False
        """
        if not hasattr(self.protocols.execution, 'download'):
            self.log.error('Protocol "' + type(self.protocols.execution).__name__ + '" does not support "download"')
            return False

        return self.protocols.execution.download()

    @watch('TargetGetSymbol')
    @action_valid_decorator_factory(TargetStates.STOPPED, 'memory')
    def get_symbol(self, symbol):
        """
        Get the address of a symbol

        :param symbol:    The name of a symbol whose address is wanted
        :returns:         (True, Address) on success else False
        """
        return self.protocols.memory.get_symbol(symbol)

    @watch('TargetWriteMemory')
    #@action_valid_decorator_factory(TargetStates.STOPPED, 'memory')
    def write_memory(self, address, size, value, num_words=1, raw=False):
        """
        Writing to memory of the target

        :param address:   The address from where the memory-write should 
                          start
        :param size:      The size of the memory write 
        :param value:     The actual value written to memory
        :type val:        int if num_words == 1 and raw == False
                          list if num_words > 1 and raw == False
                          str or byte if raw == True
        :param num_words: The amount of words to read
        :param raw:       Specifies whether to write in raw or word mode
        :returns:         True on success else False
        """
        try:
            target_range = self.avatar.get_memory_range(address)
        except Exception as e:
            self.log.warn("Performing write on undefined range at 0x%x" % address)
            target_range = None
        if target_range is not None and target_range.forwarded is True and \
        target_range.forwarded_to != self:
            return target_range.forwarded_to.write_memory(address, size, value,
                                                          num_words, raw)
        
        return self.protocols.memory.write_memory(address, size, value,
                                                  num_words, raw)

    @watch('TargetReadMemory')
    @action_valid_decorator_factory(TargetStates.STOPPED, 'memory')
    def read_memory(self, address, size, num_words=1, raw=False):
        """
        Reading from memory of the target

        :param address:     The address to read from 
        :param size:        The size of a read word
        :param num_words:   The amount of words to read (default: 1)
        :param raw:         Whether the read memory is returned unprocessed
        :return:          The read memory
        """
        try:
            target_range = self.avatar.get_memory_range(address)
        except Exception as e:
            self.log.warn("Performing write on undefined range at 0x%x" % address)
            target_range = None
        if target_range is not None and target_range.forwarded is True and \
        target_range.forwarded_to != self:
            return target_range.forwarded_to.read_memory(address, size,
                                                         num_words, raw)
        
        return self.protocols.memory.read_memory(address, size, num_words, raw)

    @watch('TargetRegisterWrite')
    #@action_valid_decorator_factory(TargetStates.STOPPED, 'registers')
    def write_register(self, register, value):
        """
        Writing a register to the target

        :param register:     The name of the register
        :param value:        The actual value written to the register
        """
        return self.protocols.registers.write_register(register, value)

    @watch('TargetRegisterRead')
    #@action_valid_decorator_factory(TargetStates.STOPPED, 'registers')
    def read_register(self, register):
        """
        Reading a register from the target

        :param register:     The name of the register
        :return:             The actual value read from the register
        """
        return self.protocols.registers.read_register(register)

    @watch('TargetSetBreakpoint')
    @action_valid_decorator_factory(TargetStates.NOT_RUNNING, 'execution')
    def set_breakpoint(self, line, hardware=False, temporary=False, regex=False,
                       condition=None, ignore_count=0, thread=0, **kwargs):
        """Inserts a breakpoint

        :param bool hardware: Hardware breakpoint
        :param bool tempory:  Tempory breakpoint
        :param str regex:     If set, inserts breakpoints matching the regex
        :param str condition: If set, inserts a breakpoint with the condition
        :param int ignore_count: Amount of times the bp should be ignored
        :param int thread:    Threadno in which this breakpoints should be added
        """
        return self.protocols.execution.set_breakpoint(line, hardware=hardware,
                                                  temporary=temporary,
                                                  regex=regex,
                                                  condition=condition,
                                                  ignore_count=ignore_count,
                                                  thread=thread, **kwargs)

    @watch('TargetSetWatchPoint')
    @action_valid_decorator_factory(TargetStates.NOT_RUNNING, 'execution')
    def set_watchpoint(self, variable, write=True, read=False):
        """Inserts a watchpoint

        :param      variable: The name of a variable or an address to watch
        :param bool write:    Write watchpoint
        :param bool read:     Read watchpoint
        """
        return self.protocols.execution.set_watchpoint(variable,
                                                  write=write,
                                                  read=read)

    @watch('TargetRemovebreakpoint')
    @action_valid_decorator_factory(TargetStates.STOPPED, 'execution')
    def remove_breakpoint(self, bkptno):
        """Deletes a breakpoint"""
        return self.protocols.execution.remove_breakpoint(bkptno)

    def update_state(self, state):
        self.log.info("State changed to to %s" % TargetStates(state))
        self.state = state

    @watch('TargetWait')
    def wait(self, state=TargetStates.STOPPED|TargetStates.EXITED):

        if state & TargetStates.SYNCING:
            self.log.warn("Waiting on SYNCING-state - this could lead to races")

        while True:
            if self.state & state != 0 and \
               (state & TargetStates.SYNCING or \
                self.state & TargetStates.SYNCING == 0):
                break
            time.sleep(.001) # send thread a ms to sleep to free resources

    def get_status(self):
        """
        Returns useful information about the target as a dict.
        """
        self.status['state'] = self.state
        return self.status

    def _get_unique_name(self, i=0):
        classname = type(self).__name__
        targetname = "{}{}".format(classname, i)
        if self.avatar and self.avatar.targets and targetname in self.avatar.targets:
            return self._get_unique_name(i + 1)
        return targetname

    def _resolve_executable_name(self):
        """
        Resolves the name of the executable for the endpoint.
        Order of operation:
            1: Check if config exists and whether target is installed
            2: Check sys_name from default config
            3: Check apt_name from default config
            4: BailOut
        """
        pass

    # ##generic aliases##
    wr = write_register
    rr = read_register
    rm = read_memory
    wm = write_memory
    bp = set_breakpoint
