from os.path import abspath
from sys import version_info

from .peripherals.avatar_peripheral import AvatarPeripheral


class MemoryRange(object):
    """
    This class represents a MemoryRange which can be mapped in one of
    Avatar-Targets.

    :ivar address:      The load-address of the memory range
    :ivar size:         The size of the memory range
    :ivar name:         User-defined name for the memory range
    :ivar permissions:  The permisions of the range, represented as textual
                        unix file permission (rwx)
    :ivar file:         A file used for backing the memory range
    :ivar file_offset:  The offset within the file
    :ivar file_bytes:   Bytes of the file to be copied into memory
    :ivar forwarded:    Enable or disable forwarding for this range
    :ivar forwarded_to: List of targets this range should be forwarded to
    :ivar is_symbolic:  Consider this range as symbolic in certain targets
    :ivar is_special:   Whether the range represents special memory which
                        behaves unlike normal memory, e.g. MMIO
    """

    def __init__(self, address, size, name=None, permissions='rwx',
                 file=None, file_offset=None, file_bytes=None, forwarded=False,
                 forwarded_to=None, is_symbolic=False, is_special=False,
                 **kwargs):
        self.address = address
        self.size = size
        self.name = (
            name
            if name is not None else
            "mem_range_0x{:08x}_0x{:08x}".format(address, address+size))
        self.permissions = permissions
        self.file = abspath(file) if file is not None else None
        self.file_offset = file_offset if file_offset is not None else None
        self.file_bytes = file_bytes if file_bytes is not None else None
        self.forwarded = forwarded
        self.is_symbolic = is_symbolic
        self.is_special = is_special
        self.forwarded_to = forwarded_to
        self.__dict__.update(kwargs)


    def dictify(self):
        """
        Returns the memory range as *printable* dictionary
        """
        # Assumption: dicts saved in mrs are of primitive types only
        expected_types = (str, bool, int, dict, AvatarPeripheral, list)
        if version_info < (3, 0): expected_types += (unicode, )

        tmp_dict = dict(self.__dict__)
        mr_dict = {}
        while tmp_dict != {}:
            k, v = tmp_dict.popitem()
            if v is None or False: continue
            elif k == 'forwarded_to': v = v.name
            # TODO handle emulate
            if not isinstance(v, expected_types):
                raise Exception(
                    "Unsupported type %s for dictifying %s for mem_range at 0x%x"
                    % (type(v), k, self.address))
            if isinstance(v, AvatarPeripheral):
                v = v.__class__.__name__
            mr_dict[k] = v
        return mr_dict


