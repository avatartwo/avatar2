from avatar2.targets import Target, TargetStates
from avatar2.protocols.inception import InceptionProtocol, IPCortexM3

from avatar2.watchmen import watch

class InceptionTarget(Target):
    '''
    Inception is a framework to perform security testing of real world
    firmware programs. The inception target and protocol allow Avatar2
    to interact with the low latency inception debugger and speed up
    read/write operations between the host and the device.

    For more information, please visit:
    https://inception-framework.github.io/inception/debugger.html

    Publication:
    Inception: System-wide security testing of real-world embedded systems
    software
    Nassim Corteggiani, Giovanni Camurati, Aurélien Francillon
    27th USENIX Security Symposium (USENIX Security 18), Baltimore, MD
    '''

    def __init__(self, avatar, 
                 processor='cortex-m3',
                 device_vendor_id=0x04b4,
                 device_product_id=0x00f1,
                 **kwargs):

        super(InceptionTarget, self).__init__(avatar, **kwargs)

        self.processor = processor
        self._device_product_id = device_product_id
        self._device_vendor_id = device_vendor_id

    @watch('TargetInit')
    def init(self):

        if self.processor == 'cortex-m3':
            inception = IPCortexM3(avatar=self.avatar, origin=self,
                    device_vendor_id=self._device_vendor_id,
                    device_product_id=self._device_product_id, 
                    output_directory=self.avatar.output_directory)
        else:
            inception = None
            self.log.warning("Target board not implemented")
            raise Exception("Target board not implemented")


        if inception.connect():
            inception.reset()
            self.update_state(TargetStates.RUNNING)
            self.log.info("Connected to Target")
        else:
            self.log.warning("Connecting failed")
            raise Exception("Connecting to target failed")

        if inception.stop():
            self.update_state(TargetStates.STOPPED)

        self.protocols.set_all(inception)
        self.protocols.monitor = inception 
        
        #self.wait()

    def reset(self):
        return self.protocols.execution.reset()

    @watch('TargetWait')
    def wait(self, state=TargetStates.STOPPED):
        return self.protocols.execution.wait(state)

