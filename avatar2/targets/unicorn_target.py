from avatar2.targets import Target, TargetStates
from avatar2.protocols.unicorn_protocol import UnicornProtocol


class UnicornTarget(Target):
    def __init__(self, avatar, **kwargs):
        super(UnicornTarget, self).__init__(avatar, **kwargs)

    def init(self):
        proto = UnicornProtocol(self.avatar, arch=self._arch, origin=self)
        self.protocols.set_all(proto)
        self.protocols.remote_memory = proto
