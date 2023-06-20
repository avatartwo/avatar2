import logging
import pprint
from types import MethodType
from threading import Thread, Event, Condition

from avatar2 import TargetStates
from avatar2.archs import ARMV7M
from avatar2.protocols.armv7_interrupt import ARMV7InterruptProtocol
from avatar2.protocols.coresight import CoreSightProtocol
from avatar2.protocols.qemu_armv7m_interrupt import QEmuARMV7MInterruptProtocol
from avatar2.targets import OpenOCDTarget, QemuTarget
from avatar2.watchmen import AFTER

from avatar2.message import RemoteInterruptEnterMessage, InterruptEnterMessage
from avatar2.message import RemoteInterruptExitMessage
from avatar2.message import RemoteMemoryWriteMessage
from avatar2.message import BreakpointHitMessage

from avatar2.watchmen import watch


def add_protocols(self, **kwargs):
    target = kwargs['watched_target']
    logging.getLogger("avatar").info(f"Attaching ARMv7 Interrupts protocol to {target}")
    if isinstance(target, OpenOCDTarget):
        # target.protocols.interrupts = CoreSightProtocol(target.avatar, target)
        target.protocols.interrupts = ARMV7InterruptProtocol(target.avatar, target)

        # We want to remove the decorators around the read_memory function of
        # this target, to allow reading while it is running (thanks oocd)
        target.read_memory = MethodType(lambda t, *args, **kwargs:
                                        t.protocols.memory.read_memory(
                                            *args, **kwargs), target
                                        )

    if isinstance(target, QemuTarget):
        target.protocols.interrupts = QEmuARMV7MInterruptProtocol(
            target, self.v7m_irq_rx_queue_name, self.v7m_irq_tx_queue_name
        )
    if getattr(target.avatar, 'irq_pair', None) is None:
        target.avatar.irq_pair = [target, ]
    else:
        target.avatar.irq_pair.append(target)
    assert len(target.avatar.irq_pair) <= 2, "Interrupts only work with two targets"


def forward_interrupt(self, message: InterruptEnterMessage):
    origin = message.origin
    self.log.warning(
        f"forward_interrupt hit with origin '{type(origin).__name__}' and message '{pprint.pformat(message.__dict__)}'")
    self.queue.put(message)

    if isinstance(origin, OpenOCDTarget):
        assert origin is self._hardware_target, "OpenOCD origin is not the hardware target"
        irq_num = message.interrupt_num
        self.log.info("Injecting IRQ 0x%x" % irq_num)
        destination = self._virtual_target
        destination.protocols.interrupts.inject_interrupt(irq_num)


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
    self._hardware_target = from_target if isinstance(from_target, OpenOCDTarget) else to_target
    self._virtual_target = to_target if not isinstance(to_target, OpenOCDTarget) else from_target
    self._irq_semi_forwarding = semi_forwarding
    self._irq_ignore = [] if disabled_irqs is None else disabled_irqs

    self._handle_remote_interrupt_enter_message = MethodType(
        _handle_remote_interrupt_enter_message, self)
    self._handle_remote_interrupt_exit_message = MethodType(
        _handle_remote_interrupt_exit_message, self)
    self._handle_remote_memory_write_message_nvic = MethodType(
        _handle_remote_memory_write_message_nvic, self)

    self.message_handlers.update({
            RemoteInterruptEnterMessage: self._handle_remote_interrupt_enter_message,
            RemoteInterruptExitMessage: self._handle_remote_interrupt_exit_message,
            InterruptEnterMessage: lambda m: None,  # Handled in the fast queue, just ignore in the main message queue
        })
    self.message_handlers.update({
        RemoteMemoryWriteMessage: self._handle_remote_memory_write_message_nvic}
    )

    # Also, let's use openocd as protocol for register and memory
    if self._hardware_target:
        self._hardware_target.protocols.memory = self._hardware_target.protocols.monitor
        self._hardware_target.protocols.registers = self._hardware_target.protocols.monitor

        self._hardware_target.protocols.interrupts.enable_interrupts()
        isr_addr = self._hardware_target.protocols.interrupts._monitor_stub_isr - 1
        self.log.info("ISR is at %#08x" % isr_addr)
        # NOTE: This won't work on many targets, eg cortex m0 can not have HW breakpoints in RAM
        # from_target.set_breakpoint(isr_addr, hardware=True)

    if self._virtual_target:
        self._virtual_target.protocols.interrupts.enable_interrupts()

    # OpenOCDProtocol does not emit breakpointhitmessages currently,
    # So we listen on state-updates and figure out the rest on our own
    self._interrupt_enter_handler = MethodType(forward_interrupt, self)
    self.fast_queue_listener.message_handlers.update({
        InterruptEnterMessage: self._interrupt_enter_handler
    })


def transfer_interrupt_state(self, to_target, from_target):
    self._hardware_target = from_target if isinstance(from_target, OpenOCDTarget) else to_target
    self._virtual_target = to_target if not isinstance(to_target, OpenOCDTarget) else from_target
    assert getattr(self, '_hardware_target', None) is not None, "Missing hardware target"
    assert getattr(self, '_virtual_target', None) is not None, "Missing virtual target"

    hw_irq_p: CoreSightProtocol = self._hardware_target.protocols.interrupts
    vm_irq_p: QEmuARMV7MInterruptProtocol = self._virtual_target.protocols.interrupts

    # Transfer the vector table location
    vtor_loc = hw_irq_p.get_vtor()
    vm_irq_p.set_vector_table_base(vtor_loc)
    # Transfer which interrupts are enabled
    enabled_interrupts = hw_irq_p.get_enabled_interrupts()
    vm_irq_p.set_enabled_interrupts(enabled_interrupts)


@watch('RemoteInterruptEnter')
def _handle_remote_interrupt_enter_message(self, message):
    self.log.warning(
        f"_handle_remote_interrupt_enter_message {self._irq_src}  -> {self._irq_dst} (message.origin={message.origin})")

    self._irq_dst.protocols.interrupts.send_interrupt_enter_response(message.id,
                                                                     True)
    if self._irq_src is None or self._irq_semi_forwarding is True:
        return

    # status = self._irq_src.get_status()
    # if status['state'] == TargetStates.STOPPED:
    #     self.log.info("Target stopped, restarting " + repr(message.origin))
    #     try:
    #         self._irq_src.cont(blocking=False)
    #     except:
    #         self.log.exception(" ")


@watch('RemoteInterruptExit')
def _handle_remote_interrupt_exit_message(self, message: RemoteInterruptExitMessage):
    """
    Handle an interrupt exiting properly
    If the interrupt was trigged by the hardware, we need to tell the
    interrupt that we satisified it
    :param self:
    :param message:
    :return:
    """
    self.log.warning(
        f"_handle_remote_interrupt_exit_message {self._irq_src}  -> {self._irq_dst} (message.origin={message.origin})")

    origin = message.origin
    if origin is self._virtual_target:
        self._hardware_target.protocols.interrupts.inject_exc_return()

    # Always ack the exit message
    self._irq_dst.protocols.interrupts.send_interrupt_exit_response(message.id,
                                                                    True)


def _handle_remote_memory_write_message_nvic(self, message: RemoteMemoryWriteMessage):
    # self.log.critical(f"_handle_remote_memory_write_message_nvic 0x{message.address:x} -> 0x{message.value:x}")
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
    avatar.enable_interrupt_forwarding = MethodType(enable_interrupt_forwarding, avatar)
    avatar.transfer_interrupt_state = MethodType(transfer_interrupt_state, avatar)

    avatar.watchmen.add_watchman('TargetInit', when=AFTER, callback=add_protocols)
