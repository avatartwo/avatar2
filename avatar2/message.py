

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
        super(self.__class__, self).__init__(origin, TargetStates.STOPPED)
        self.breakpoint_number = breakpoint_number
        self.address = address


class RemoteMemoryReadMessage(AvatarMessage):
    def __init__(self, origin, id, pc, address, size):
        super(self.__class__, self).__init__(origin)
        self.id = id
        self.pc = pc
        self.address = address
        self.size = size
        self.num_words = 1
        self.raw = False


class RemoteMemoryWriteMessage(AvatarMessage):
    def __init__(self, origin, id, pc, address, value, size):
        super(self.__class__, self).__init__(origin)
        self.id = id
        self.pc = pc
        self.address = address
        self.value = value
        self.size = size

from .targets.target import TargetStates
