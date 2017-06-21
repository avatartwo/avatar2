class AvatarMessage(object):
    """This class provides constants to create and parse the avatar message-dict"""

    def __init__(self, origin):
        self.origin = origin

    def __str__(self):
        if self.origin:
            return "%s from %s" % (self.__class__.__name__, self.origin.name)
        else:
            return "%s from unkown origin" % self.__class__.__name__


class UpdateStateMessage(AvatarMessage):
    def __init__(self, origin, new_state):
        super(self.__class__, self).__init__(origin)
        self.state = new_state


class BreakpointHitMessage(AvatarMessage):
    def __init__(self, origin, breakpoint_number, address):
        super(self.__class__, self).__init__(origin)
        self.breakpoint_number = breakpoint_number
        self.address = address


class RemoteMemoryReadMessage(AvatarMessage):
    def __init__(self, origin, id, address, size):
        super(self.__class__, self).__init__(origin)
        self.id = id
        self.address = address
        self.size = size


class RemoteMemoryWriteMessage(AvatarMessage):
    def __init__(self, origin, id, address, value, size):
        super(self.__class__, self).__init__(origin)
        self.id = id
        self.address = address
        self.value = value
        self.size = size
