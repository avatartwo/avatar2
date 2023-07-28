from typing import Union, List


class FuncArg:
    def __init__(self, value: int | None, needs_transfer=False, size=None):
        assert value is None or isinstance(value, int), "Address must be an integer or None for read from register"
        if needs_transfer:
            assert isinstance(size, int), "Size must be specified if needs_transfer is True"
        self.value: int = value
        self.needs_transfer: bool = needs_transfer
        self.size: int = size

    def __str__(self):
        if self.needs_transfer:
            return f"FuncArg(value=0x{self.value:x}, needs_transfer=True, size={self.size})"
        else:
            return f"FuncArg(value=0x{self.value:x})"

    def __repr__(self):
        return str(self)


class FuncReturnArg(FuncArg):
    def __init__(self, value: int, needs_transfer=True, size=None):
        super().__init__(value, needs_transfer=needs_transfer, size=size)


class HALFunction:

    def __init__(self, address: int, args: [FuncArg], return_args: Union[List[FuncReturnArg], None] = None):
        self.address = address
        self.args = args
        self.return_args = return_args

    def __str__(self):
        return f"HALFunction(address=0x{self.address:x}, args={self.args}, returnArgs={self.return_args})"

    def __repr__(self):
        return str(self)
