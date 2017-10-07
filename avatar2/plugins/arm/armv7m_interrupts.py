
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

from avatar2.watchmen import watch

def add_protocols(self, **kwargs):
    target = kwargs['watched_target']
    #import IPython; IPython.embed()
    if isinstance(target, OpenOCDTarget):
        target.protocols.interrupts = CoreSightProtocol(target.avatar,
                                                        target)
    if isinstance(target, QemuTarget):
        target.protocols.interrupts = ARMV7MInterruptProtocol(
            target, self.v7m_irq_rx_queue_name, self.v7m_irq_tx_queue_name,
        )


def enable_interrupt_forwarding(self, from_target, to_target):
    self.message_handlers.update(
        {RemoteInterruptEnterMessage: handle_remote_interrupt_enter_message,
         RemoteInterruptExitMessage: handle_remote_interrupt_exit_message}    
    )

    from_target.protocols.interrupts.enable_interrupts()
    to_target.protocols.interrupts.enable_interrupts()


@watch('RemoteInterruptEnter')
def handle_remote_interrupt_enter_message(self, message):
    if message.transition_type == 1 and \
       message.interrupt_num != 0 and message.interrupt_num != 62:
        self.interrupt_sink._interrupt_protocol.inject_interrupt(
            message.interrupt_num)

@watch('RemoteInterruptExit')
def handle_remote_interrupt_exit_message(self, message):
    # TODO Implement stub and so on
    from_target.protocols.send_interrupt_exit_response(message.id,
                                                       message.success)


def load_plugin(avatar):
    if avatar.arch != ARMV7M:
        avatar.log.error("Tried to load armv7-m interrupt plugin " +
                         "with mismatching architecture")

    avatar.v7m_irq_rx_queue_name = '/avatar_v7m_irq_rx_queue'
    avatar.v7m_irq_tx_queue_name = '/avatar_v7m_irq_tx_queue'
    avatar.enable_interrupts = MethodType(enable_interrupt_forwarding, avatar)

    avatar.watchmen.add_watchman('TargetInit', when=AFTER,
                                 callback=add_protocols)


