from avatar2.peripherals import AvatarPeripheral
import logging


class InspectionPeripheral(AvatarPeripheral):
    """AvatarPeripheral to inspect all accesses to its memory region"""

    def __init__(self, name, address, size):
        super().__init__(name, address, size)
        self.read_handler[0:size] = self.dispatch_read
        self.write_handler[0:size] = self.dispatch_write
        self.log = logging.getLogger('emulated')

    def dispatch_read(self, offset, size, *args, **kwargs):
        self.log.debug(
            f"Memory read at 0x{self.address:x} 0x{offset:x} with size {size} from {kwargs['origin'].__class__.__name__}")
        return kwargs['origin'].protocols.memory.read_memory(self.address + offset, size)

    def dispatch_write(self, offset, size, value, *args, **kwargs):
        self.log.debug(
            f"Memory write at 0x{self.address:x} 0x{offset:x} with size {size} and value 0x{value:x} from {kwargs['origin'].__class__.__name__}")
        return kwargs['origin'].protocols.memory.write_memory(self.address + offset, size, value)


class PartialForwardingPeripheral(AvatarPeripheral):
    """AvatarPeripheral to forward all accesses except some to its memory region"""
    read_supports_pc = True
    write_supports_pc = True

    def __init__(self, name, address, size, emulate_config):
        super().__init__(name, address, size)
        self.read_handler[0:size] = self.dispatch_read
        self.write_handler[0:size] = self.dispatch_write
        self.log = logging.getLogger('emulated')

        self.forward_to = None if 'forward_to' not in emulate_config else emulate_config['forward_to']
        self.ignore_write_offsets = [] if 'ignore_forward_write_offsets' not in emulate_config else emulate_config[
            'ignore_forward_write_offsets']
        self.ignore_read_offsets = [] if 'ignore_forward_read_offsets' not in emulate_config else emulate_config[
            'ignore_forward_read_offsets']
        self.ignore = [] if 'ignore' not in emulate_config else emulate_config['ignore']

    def dispatch_read(self, offset, size, pc, *args, **kwargs):
        if offset in self.ignore:
            self.log.warning(f"DROPPING read to 0x{self.address + offset:x}")
            return 0
        elif offset in self.ignore_read_offsets:
            self.log.debug(
                f"pc=0x{pc:x} NOT forwarded memory read at 0x{self.address + offset:x} with size {size} of {kwargs['origin'].__class__.__name__}")
            return kwargs['origin'].protocols.memory.read_memory(self.address + offset, size)
        else:
            self.log.debug(f"pc=0x{pc:x} Forwarding read at {hex(self.address + offset)} with size {size}")
            return self.forward_to.protocols.memory.read_memory(self.address + offset, size)

    def dispatch_write(self, offset, size, value, pc, *args, **kwargs):
        if offset in self.ignore:
            self.log.warning(f"DROPPING write to 0x{self.address + offset:x} with {value} (0x{value:x})")
            return (True, True)
        elif offset in self.ignore_write_offsets:
            self.log.debug(
                f"pc=0x{pc:x} NOT forwarded memory write at 0x{self.address + offset:x} with size {size} and value {value} (0x{value:x}) of {kwargs['origin'].__class__.__name__}")
            return kwargs['origin'].protocols.memory.write_memory(self.address + offset, size, value)
        else:
            self.log.debug(
                f"pc=0x{pc:x} Forwarding write at {hex(self.address + offset)} with value {value} (0x{value:x})")
            return self.forward_to.protocols.memory.write_memory(self.address + offset, size,
                                                                 value), True  # True to signal QEmu to not process this register write further


class PeripheralTracePeripheral(AvatarPeripheral):
    """AvatarPeripheral to forward all accesses except some to its memory region"""

    read_supports_pc = True
    write_supports_pc = True

    def __init__(self, name, address, size, emulate_config):
        super().__init__(name, address, size)
        self.read_handler[0:size] = self.dispatch_read
        self.write_handler[0:size] = self.dispatch_write
        self.log = logging.getLogger('emulated')

        self.forward_to = None if 'forward_to' not in emulate_config else emulate_config['forward_to']
        self.peripheral_register = {} if 'peripheral_register' not in emulate_config else emulate_config[
            'peripheral_register']
        self.register_offsets = self.peripheral_register.keys()
        self.trace = []

    def dispatch_read(self, offset, size, *args, **kwargs):
        reg = self.peripheral_register[offset] if offset in self.peripheral_register else "UNKNOWN"
        value = self.forward_to.protocols.memory.read_memory(self.address + offset, size)
        self.log.debug(
            f"pc=0x{kwargs['pc']:x} : Register read of {reg} at 0x{offset:04x} with value {value} (0x{value:x})")
        self.trace.append(('read', offset, reg, value))
        return value

    def dispatch_write(self, offset, size, value, *args, **kwargs):
        reg = self.peripheral_register[offset] if offset in self.peripheral_register else "UNKNOWN"
        self.log.debug(
            f"pc=0x{kwargs['pc']:x} : Register write of {reg} at 0x{offset:04x} with value {value} (0x{value:x})")
        self.trace.append(('write', offset, reg, value))
        return self.forward_to.protocols.memory.write_memory(self.address + offset, size, value)
