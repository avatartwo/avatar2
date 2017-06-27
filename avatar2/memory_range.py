

class MemoryRange(object):
    """
    This class represents a MemoryRange which can be mapped in one of Avatar-Targets.
    :ivar address:      The load-address of the memory range
    :ivar size:         The size of the memory range
    :ivar name:         User-defined name for the memory range
    :ivar permissions:  The permisions of the range, represented as textual unix file permission (rwx)
    :ivar file:         A file used for backing the memory range
    :ivar forwarded:    Enable or disable forwarding for this range
    :ivar forwarded_to: List of targets this range should be forwarded to
    """
    mem_range_count = 0

    def __init__(self, address, size, name=None, permissions='rwx',
                 file=None, forwarded=False, forwarded_to=None, **kwargs):
        self.address = address
        self.size = size
        self.name = name if name else "mem{}[{}-{}]".format(MemoryRange.mem_range_count, hex(address), hex(size))
        self.permissions = permissions
        self.file = file
        self.forwarded = forwarded
        self.forwarded_to = forwarded_to
        self.__dict__.update(kwargs)

        MemoryRange.mem_range_count += 1
