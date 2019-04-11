import sys
from avatar2.targets import Target, TargetStates
from avatar2.protocols.jlink import JLinkProtocol
from avatar2.watchmen import watch

if sys.version_info < (3, 0):
    from Queue import PriorityQueue
else:
    from queue import PriorityQueue


class JLinkTarget(Target):
    def __init__(self, avatar, serial, device, **kwargs):
        """
        Create a JLink target instance
        :param avatar: The avatar instance
        :param serial: The JLink's serial number
        :param device: The Device string to use (e.g., ARM7, see JlinkExe for the list)
        :param kwargs:
        """
        super(JLinkTarget, self).__init__(avatar, **kwargs)
        self.avatar = avatar
        self.serial = serial
        self.device = device

    @watch("TargetInit")
    def init(self):
        jlink = JLinkProtocol(serial=self.serial, device=self.device, avatar=self.avatar, origin=self)
        self.protocols.set_all(jlink)
        if jlink.jlink.halted():
            self.state = TargetStates.STOPPED
        else:
            self.state = TargetStates.RUNNING
        #self.wait()

    def reset(self, halt=True):
        self.protocols.execution.reset(halt=halt)