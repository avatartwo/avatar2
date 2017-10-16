
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
    if isinstance(target, OpenOCDTarget):
        target.protocols.interrupts = CoreSightProtocol(target.avatar,
                                                        target)
    if isinstance(target, QemuTarget):
        target.protocols.interrupts = ARMV7MInterruptProtocol(
            target, self.v7m_irq_rx_queue_name, self.v7m_irq_tx_queue_name
        )


def enable_interrupt_forwarding(self, from_target, to_target,
                                disabled_irqs=None):
    self._irq_src = from_target
    self._irq_dst = to_target
    self._irq_ignore = [] if disabled_irqs is None else disabled_irqs

    self._handle_remote_interrupt_enter_message = MethodType(_handle_remote_interrupt_enter_message, avatar)
    self._handle_remote_interrupt_exit_message = MethodType(_handle_remote_interrupt_exit_message, avatar)
    self._handle_remote_memory_write_message_nvic = MethodType(_handle_remote_memory_write_message_nvic)

    self.fast_queue_listener.message_handlers.update(
        {RemoteInterruptEnterMessage: self._handle_remote_interrupt_enter_message,
         RemoteInterruptExitMessage: self._handle_remote_interrupt_exit_message}    
    )
    self.message_handlers.update(
        RemoteMemoryWriteMessage: self._handle_remote_memory_write_message_nvic
    )

    from_target.protocols.interrupts.enable_interrupts()
    to_target.protocols.interrupts.enable_interrupts()


@watch('RemoteInterruptEnter')
def _handle_remote_interrupt_enter_message(self, message):
    if message.transition_type == 1 and \
       message.interrupt_num not in self._irq_ignore:
        self._irq_dst.protocols.interrupts.inject_interrupt(
            message.interrupt_num)

@watch('RemoteInterruptExit')
def _handle_remote_interrupt_exit_message(self, message):
    # TODO Implement stub and so on
    self._irq_dst.protocols.interrupts.send_interrupt_exit_response(message.id,
                                                       True)

@watch('RemoteMemoryWrite')
def _handle_remote_memory_write_message_nvic(self, message):
    # NVIC address according to coresight manual
    if message.address < 0xe000e000 or message.address > 0xe000f000:
        return self._handle_remote_memory_write_message(message)

    # Discard writes to the vector table offset registers
    # TODO add other blacklists
    if message.address == 0xE000ED08:
        success = True
    else:
        success = mem_range.forwarded_to.write_memory(message.address,
                                                      message.size,
                                                      message.value)

    message.origin.protocols.remote_memory.send_response(message.id, 0,
                                                         success)
    return message.id, 0, success


def load_plugin(avatar):
    if avatar.arch != ARMV7M:
        avatar.log.error("Tried to load armv7-m interrupt plugin " +
                         "with mismatching architecture")

    avatar.v7m_irq_rx_queue_name = '/avatar_v7m_irq_rx_queue'
    avatar.v7m_irq_tx_queue_name = '/avatar_v7m_irq_tx_queue'
    avatar.enable_interrupts = MethodType(enable_interrupt_forwarding, avatar)

    avatar.watchmen.add_watchman('TargetInit', when=AFTER,
                                 callback=add_protocols)


