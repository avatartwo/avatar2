from .plugins.arm.hal import HALFunction


class AvatarMessage(object):
    def __init__(self, origin):
        self.origin = origin

    def __str__(self):
        if self.origin:
            return "%s from %s" % (self.__class__.__name__, self.origin.name)
        else:
            return "%s from unkown origin" % self.__class__.__name__


class UpdateStateMessage(AvatarMessage):
    def __init__(self, origin, new_state):
        super(UpdateStateMessage, self).__init__(origin)
        self.state = new_state


class BreakpointHitMessage(UpdateStateMessage):
    def __init__(self, origin, breakpoint_number, address):
        super(BreakpointHitMessage, self).__init__(origin, TargetStates.BREAKPOINT)
        self.breakpoint_number = breakpoint_number
        self.address = address


class SyscallCatchedMessage(BreakpointHitMessage):
    def __init__(self, origin, breakpoint_number, address, type='entry'):
        super(self.__class__, self).__init__(origin, breakpoint_number, address)
        self.type = type


class RemoteMemoryReadMessage(AvatarMessage):
    def __init__(self, origin, id, pc, address, size, dst=None):
        super(self.__class__, self).__init__(origin)
        self.id = id
        self.pc = pc
        self.address = address
        self.size = size
        self.dst = dst
        self.num_words = 1
        self.raw = False


class RemoteMemoryWriteMessage(AvatarMessage):
    def __init__(self, origin, id, pc, address, value, size, dst=None):
        super(self.__class__, self).__init__(origin)
        self.id = id
        self.pc = pc
        self.address = address
        self.value = value
        self.size = size
        self.dst = dst


class RemoteInterruptEnterMessage(AvatarMessage):
    def __init__(self, origin, id, interrupt_num):
        super(self.__class__, self).__init__(origin)
        self.id = id
        self.interrupt_num = interrupt_num


class RemoteInterruptExitMessage(AvatarMessage):
    def __init__(self, origin, id, transition_type, interrupt_num):
        super(self.__class__, self).__init__(origin)
        self.id = id
        self.transition_type = transition_type
        self.interrupt_num = interrupt_num


class TargetInterruptEnterMessage(AvatarMessage):
    def __init__(self, origin, id, interrupt_num, isr_addr):
        super(self.__class__, self).__init__(origin)
        self.id = id
        self.interrupt_num = interrupt_num
        self.isr_addr = isr_addr


class TargetInterruptExitMessage(AvatarMessage):
    def __init__(self, origin, id, interrupt_num, isr_addr):
        super(self.__class__, self).__init__(origin)
        self.id = id
        self.interrupt_num = interrupt_num
        self.isr_addr = isr_addr


class HALEnterMessage(AvatarMessage):
    def __init__(self, origin, function: HALFunction, return_address: int):
        super(self.__class__, self).__init__(origin)
        self.function = function
        self.return_address = return_address

    def __str__(self):
        return f"{self.__class__.__name__} from {self.origin.name} returning to 0x{self.return_address:x}"

    def __repr__(self):
        return self.__str__()


class HALExitMessage(AvatarMessage):
    def __init__(self, origin, function: HALFunction, return_val: int, return_address: int):
        super(self.__class__, self).__init__(origin)
        self.function = function
        self.return_val = return_val
        self.return_address = return_address

    def __str__(self):
        return f"{self.__class__.__name__} from {self.origin.name} to 0x{self.return_address:x} with return_value 0x{self.return_val:x}"

    def __repr__(self):
        return self.__str__()


from .targets.target import TargetStates
