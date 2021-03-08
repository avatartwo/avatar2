import sys

from intervaltree import IntervalTree
from inspect import signature

if sys.version_info.major == 3 and sys.version_info.minor >= 8:
    from functools import cached_property
else:
    from cached_property import cached_property



class AvatarPeripheral(object):
    def __init__(self, name, address, size, **kwargs):
        self.name = name if name else "%s_%x" % (self.__class__.__name__, address)
        self.address = address
        self.size = size
        self.read_handler = IntervalTree()
        self.write_handler = IntervalTree()

    @cached_property
    def read_supports_pc(self):
        """
        Checks if all registered read-handlers support an pc parameter
        """
        return all("pc" in signature(rh.data).parameters for rh in self.read_handler)

    @cached_property
    def write_supports_pc(self):
        """
        Checks if all registered read-handlers support an pc parameter
        """
        return all("pc" in signature(rh.data).parameters for rh in self.write_handler)

    def shutdown(self):
        """
        Some peripherals will require to be shutdowned when avatar exits.
        In those cases, this method should be overwritten.
        """
        pass

    def write_memory(self, address, size, value, num_words=1, raw=False, pc=0):

        if num_words != 1 or raw is True:
            raise Exception(
                "write_memory for AvatarPeripheral does not support \
                             'num_words' or 'raw' kwarg"
            )

        offset = address - self.address
        intervals = self.write_handler[offset : offset + size]
        if intervals == set():
            raise Exception(
                "No write handler for peripheral %s at offset %d \
                            (0x%x)"
                % (self.name, offset, address)
            )
        if len(intervals) > 1:
            raise Exception(
                "Multiple write handler for peripheral %s\
                            at offset %d"
                % (self.name, offset)
            )

        kwargs = {} if self.write_supports_pc is False else {"pc": pc}
        return intervals.pop().data(offset, size, value, **kwargs)

    def read_memory(self, address, size, num_words=1, raw=False, pc=0):
        if num_words != 1 or raw is True:
            raise Exception(
                "read_memory for AvatarPeripheral does not support \
                             'num_words' or 'raw' kwarg"
            )

        offset = address - self.address
        intervals = self.read_handler[offset : offset + size]

        if intervals == set():
            raise Exception(
                "No read handler for peripheral %s at offset %d \
                            (0x%x)"
                % (self.name, offset, address)
            )
        if len(intervals) > 1:
            raise Exception(
                "Multiple read handler for peripheral %s\
                            at offset %d"
                % (self.name, offset)
            )
        kwargs = {} if self.write_supports_pc is False else {"pc": pc}
        return intervals.pop().data(offset, size, **kwargs)
