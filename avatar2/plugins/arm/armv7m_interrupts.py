from types import MethodType
from threading import Thread, Event, Condition

from avatar2 import TargetStates
from avatar2.archs import ARMV7M
from avatar2.protocols.coresight import CoreSightProtocol
from avatar2.protocols.armv7m_interrupt import ARMV7MInterruptProtocol
from avatar2.targets import OpenOCDTarget, QemuTarget
from avatar2.watchmen import AFTER

from avatar2.message import RemoteInterruptEnterMessage
from avatar2.message import RemoteInterruptExitMessage
from avatar2.message import RemoteMemoryWriteMessage
from avatar2.message import BreakpointHitMessage

from avatar2.watchmen import watch


def add_protocols(self, **kwargs):
    target = kwargs['watched_target']
    if isinstance(target, OpenOCDTarget):
        target.protocols.interrupts = CoreSightProtocol(target.avatar,
                                                        target)
        # We want to remove the decorators around the read_memory function of
        # this target, to allow reading while it is running (thanks oocd)
        target.read_memory = MethodType( lambda t, *args, **kwargs:
                                        t.protocols.memory.read_memory(
                                            *args, **kwargs), target
                                       )
        # Also, let's use openocd as protocol for register and memory
        target.protocols.memory = target.protocols.monitor
        target.protocols.register = target.protocols.monitor

        
    if isinstance(target, QemuTarget):
        target.protocols.interrupts = ARMV7MInterruptProtocol(
            target, self.v7m_irq_rx_queue_name, self.v7m_irq_tx_queue_name
        )


def forward_interrupt(self, message):  # , **kwargs):
    global stawp
    target = message.origin
    target.update_state(message.state)
    self.queue.put(message)

    if isinstance(target, OpenOCDTarget):
        if message.address == message.origin.protocols.interrupts._monitor_stub_isr - 1:
            xpsr = target.read_register('xPSR')
            irq_num = xpsr & 0xff
            self.log.info("Injecting IRQ 0x%x" % irq_num)
            self._irq_dst.protocols.interrupts.inject_interrupt(irq_num)


def gontinue_execution(self, message, **kwargs):
    target = message.origin
    if message.address == message.origin.protocols.interrupts._monitor_stub_isr - 1:
        target.cont()


def enable_interrupt_forwarding(self, from_target, to_target=None,
                                disabled_irqs=None, semi_forwarding=False):
    """
    Semi forwarding is a special mode developed for pretender.
    It allows that irqs are taken from from_target and external calls to
    inject_interrupt. However, no information about to_targets irq-state is
    given back to from_target. Nevertheless, memory requests from to_target to
    from_target are forwarded.
    Confused yet? So are we, this is a huge hack.
    """
    self._irq_src = from_target
    self._irq_dst = to_target
    self._irq_semi_forwarding = semi_forwarding
    self._irq_ignore = [] if disabled_irqs is None else disabled_irqs

    self._handle_remote_interrupt_enter_message = MethodType(
        _handle_remote_interrupt_enter_message, self)
    self._handle_remote_interrupt_exit_message = MethodType(
        _handle_remote_interrupt_exit_message, self)
    self._handle_remote_memory_write_message_nvic = MethodType(
        _handle_remote_memory_write_message_nvic, self)

    self.message_handlers.update(
        {
            RemoteInterruptEnterMessage: self._handle_remote_interrupt_enter_message,
            RemoteInterruptExitMessage: self._handle_remote_interrupt_exit_message}
    )
    self.message_handlers.update(
        {
            RemoteMemoryWriteMessage: self._handle_remote_memory_write_message_nvic}
    )

    if from_target:
        from_target.protocols.interrupts.enable_interrupts()
        isr_addr = from_target.protocols.interrupts._monitor_stub_isr - 1
        self.log.info("ISR breakpoint at %#08x" % isr_addr)
        from_target.set_breakpoint(isr_addr, hardware=True)
    if to_target:
        to_target.protocols.interrupts.enable_interrupts()

    # OpenOCDProtocol does not emit breakpointhitmessages currently,
    # So we listen on state-updates and figure out the rest on our own
    # self.watchmen.add_watchman('BreakpointHit', when=AFTER,
    #                             callback=continue_execution)
    self._handle_breakpoint_handler = MethodType(forward_interrupt, self)
    self.fast_queue_listener.message_handlers.update({
        BreakpointHitMessage: self._handle_breakpoint_handler
    }
    )

    # def _fast_handle_update_state_message(self, message):
    # print message
    # message.origin.update_state(message.state)
    # self.avatar.queue.put(message)


@watch('RemoteInterruptEnter')
def _handle_remote_interrupt_enter_message(self, message):
    self._irq_dst.protocols.interrupts.send_interrupt_enter_response(message.id,
                                                                     True)
    if self._irq_src is None or self._irq_semi_forwarding is True:
        return

    
    status = self._irq_src.get_status()
    if status['state'] == TargetStates.STOPPED:
        self.log.info("Target stopped, restarting " + repr(message.origin))
        try:
            self._irq_src.cont(blocking=False)
        except:
            self.log.exception(" ")



@watch('RemoteInterruptExit')
def _handle_remote_interrupt_exit_message(self, message):
    """
    Handle an interrupt exiting properly
    If the interrupt was trigged by the hardware, we need to tell the
    interrupt that we satisified it
    :param self:
    :param message:
    :return:
    """
    if self._irq_src is not None and self._irq_semi_forwarding is False:
        # We are forwarding, make sure to forward the return
        self._irq_src.protocols.interrupts.inject_exc_return(
            message.transition_type)

    # Always ack the exit message
    self._irq_dst.protocols.interrupts.send_interrupt_exit_response(message.id,
                                                                    True)


def _handle_remote_memory_write_message_nvic(self, message):
    # NVIC address according to coresight manual
    if message.address < 0xe000e000 or message.address > 0xe000f000 or self._irq_src is None:
        return self._handle_remote_memory_write_message(message)

    # Discard writes to the vector table offset registers
    # TODO add other blacklists
    if message.address == 0xE000ED08:
        success = True
    else:
        success = self._irq_src.write_memory(message.address,
                                             message.size,
                                             message.value)

    message.origin.protocols.remote_memory.send_response(message.id, 0,
                                                         success)
    return message.id, message.value, success


def load_plugin(avatar):
    if avatar.arch != ARMV7M:
        avatar.log.error("Tried to load armv7-m interrupt plugin " +
                         "with mismatching architecture")

    avatar.v7m_irq_rx_queue_name = '/avatar_v7m_irq_rx_queue'
    avatar.v7m_irq_tx_queue_name = '/avatar_v7m_irq_tx_queue'
    avatar.enable_interrupts = MethodType(enable_interrupt_forwarding, avatar)

    avatar.watchmen.add_watchman('TargetInit', when=AFTER,
                                 callback=add_protocols)
