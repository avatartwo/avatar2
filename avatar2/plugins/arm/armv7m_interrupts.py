import logging
import pprint
from time import sleep
from types import MethodType

from avatar2 import Avatar, TargetStates
from avatar2.archs import ARMV7M
from avatar2.protocols.armv7_interrupt import ARMV7InterruptProtocol
from avatar2.protocols.coresight import CoreSightProtocol
from avatar2.protocols.qemu_armv7m_interrupt import QEmuARMV7MInterruptProtocol
from avatar2.targets import OpenOCDTarget, QemuTarget
from avatar2.watchmen import AFTER

from avatar2.message import RemoteInterruptEnterMessage, TargetInterruptEnterMessage, TargetInterruptExitMessage
from avatar2.message import RemoteInterruptExitMessage
from avatar2.message import RemoteMemoryWriteMessage

from avatar2.watchmen import watch


def add_protocols(self: Avatar, **kwargs):
    target = kwargs['watched_target']
    logging.getLogger("avatar").info(f"Attaching ARMv7 Interrupts protocol to {target}")
    if isinstance(target, OpenOCDTarget):
        software_irqs = [] if 'software_irqs' not in self._plugins_armv7m_interrupts_config else \
            self._plugins_armv7m_interrupts_config['software_irqs']
        target.protocols.interrupts = ARMV7InterruptProtocol(target.avatar, target, software_irqs)

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


def enable_interrupt_forwarding(self, from_target, to_target=None):
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

    self._handle_remote_interrupt_enter_message = MethodType(_handle_remote_interrupt_enter_message, self)
    self._handle_remote_interrupt_exit_message = MethodType(_handle_remote_interrupt_exit_message, self)
    self._handle_remote_memory_write_message_nvic = MethodType(_handle_remote_memory_write_message_nvic, self)

    self.message_handlers.update({
        RemoteMemoryWriteMessage: self._handle_remote_memory_write_message_nvic}
    )

    # OpenOCDProtocol does not emit breakpointhitmessages currently,
    # So we listen on state-updates and figure out the rest on our own
    self._interrupt_enter_handler = MethodType(forward_interrupt, self)
    self.fast_queue_listener.message_handlers.update({
        RemoteInterruptEnterMessage: self._handle_remote_interrupt_enter_message,
        RemoteInterruptExitMessage: self._handle_remote_interrupt_exit_message,
        TargetInterruptEnterMessage: self._interrupt_enter_handler,
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


@watch("TargetInterruptEnter")
def forward_interrupt(self, message: TargetInterruptEnterMessage):
    origin = message.origin
    assert origin is self._hardware_target, "Origin is not the hardware target"
    self.log.info(f"forwarding interrupt {message.interrupt_num}")

    if self._virtual_target.state != TargetStates.RUNNING:
        self.log.critical(f"Interrupt destination not running, pushing irq={message.interrupt_num} onto queue")
        self._hardware_target.protocols.interrupts.queue_irq(message.interrupt_num, message.isr_addr)
        return False
    if self._plugins_armv7m_interrupts_injected_irq is not None:
        self.log.critical(f"Interrupt nesting not supported, pushing irq={message.interrupt_num} onto queue")
        self._hardware_target.protocols.interrupts.queue_irq(message.interrupt_num, message.isr_addr)
        return False

    # self.queue.put(message)

    irq_num = message.interrupt_num
    self.log.info("Injecting IRQ 0x%x" % irq_num)
    # State update MUST be before signaling the protocol due to async processing
    self._plugins_armv7m_interrupts_injected_irq = irq_num
    self._plugins_armv7m_interrupts_from_hardware = True
    self.log.warning(f"forward_interrupt {self._plugins_armv7m_interrupts_from_hardware})")
    destination = self._virtual_target
    destination.protocols.interrupts.inject_interrupt(irq_num)
    return True


@watch('RemoteInterruptEnter')
def _handle_remote_interrupt_enter_message(self, message):
    self.log.warning(
        f"_handle_remote_interrupt_enter_message {self._plugins_armv7m_interrupts_from_hardware})")
    self._plugins_armv7m_interrupts_injected_irq = message.interrupt_num

    if not self._plugins_armv7m_interrupts_from_hardware:
        self._plugins_armv7m_interrupts_from_hardware = True
        self._hardware_target.protocols.interrupts.inject_interrupt(message.interrupt_num)

    self._irq_dst.protocols.interrupts.send_interrupt_enter_response(message.id,
                                                                     True)
    # if self._irq_src is None or self._irq_semi_forwarding is True:
    #     return

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
    self.log.warning(f"_handle_remote_interrupt_exit_message {message})")

    origin = message.origin
    if origin is self._virtual_target and self._plugins_armv7m_interrupts_injected_irq is not None:
        if self._plugins_armv7m_interrupts_from_hardware:
            self._hardware_target.protocols.interrupts.inject_exc_return()
            self._plugins_armv7m_interrupts_from_hardware = False
        self._plugins_armv7m_interrupts_injected_irq = None

    # Always ack the exit message
    self._irq_dst.protocols.interrupts.send_interrupt_exit_response(message.id, True)


def _handle_remote_memory_write_message_nvic(self, message: RemoteMemoryWriteMessage):
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
    drop_further_processing = 0
    if isinstance(success, tuple):
        success, drop_further_processing = success

    message.origin.protocols.remote_memory.send_response(message.id, drop_further_processing, success)

    return message.id, message.value, success


def load_plugin(avatar, config={}):
    if avatar.arch not in ARMV7M:
        avatar.log.error("Tried to load armv7-m interrupt plugin " +
                         "with mismatching architecture")

    avatar.v7m_irq_rx_queue_name = '/avatar_v7m_irq_rx_queue'
    avatar.v7m_irq_tx_queue_name = '/avatar_v7m_irq_tx_queue'
    avatar.enable_interrupt_forwarding = MethodType(enable_interrupt_forwarding, avatar)
    avatar.transfer_interrupt_state = MethodType(transfer_interrupt_state, avatar)
    avatar._plugins_armv7m_interrupts_injected_irq = None
    avatar._plugins_armv7m_interrupts_from_hardware = False
    avatar._plugins_armv7m_interrupts_config = config

    avatar.watchmen.add_watchman('TargetInit', when=AFTER, callback=add_protocols)
