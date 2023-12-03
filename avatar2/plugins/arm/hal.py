from typing import Union, List


class FuncArg:
    """
    Represents a function argument that is written to the hardware target.
    By default, this is a constant value, for argument transfer at runtime use RegisterFuncArg.
    """

    def __init__(self, value, needs_transfer=False, size=None):
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


class RegisterFuncArg(FuncArg):
    """Represents a function argument that is passed in a register and dynamically transferred to the hardware target"""

    def __init__(self, register: str, needs_transfer=False, size=None):
        super().__init__(None, needs_transfer=needs_transfer, size=size)
        self.register = register

    def __str__(self):
        if self.needs_transfer:
            return f"RegisterFuncArg(register={self.register}, value={self.value}, needs_transfer=True, size={self.size})"
        else:
            return f"RegisterFuncArg(register={self.register}, value={self.value})"


class FuncReturnArg(FuncArg):
    def __init__(self, value: int, needs_transfer=True, size=None):
        super().__init__(value, needs_transfer=needs_transfer, size=size)

    def __str__(self):
        if self.needs_transfer:
            return f"FuncReturnArg(value=0x{self.value:x}, needs_transfer=True, size={self.size})"
        else:
            return f"FuncReturnArg(value=0x{self.value:x})"


class ContextTransferArg(FuncArg):
    def __init__(self, address: int, size=None):
        super().__init__(address, needs_transfer=True, size=size)

    def __str__(self):
        if self.needs_transfer:
            return f"ContextTransferArg(value=0x{self.value:x}, needs_transfer=True, size={self.size})"
        else:
            return f"ContextTransferArg(value=0x{self.value:x})"


class HWFunction:
    """
    Represents a function that is called on the hardware target.

    @param address: The address of the function
    @param args: The arguments of the function
    @param return_args: The return arguments of the function; if [None] -> void function ;
                otherwise it assumes the return value in r0
    """

    VOID = [None]

    def __init__(self, address: int, args: [FuncArg], context_transfers: [FuncArg] = [],
                 return_args: Union[List[Union[FuncReturnArg, None]], None] = None):
        self.address = address
        self.args = args
        self.context_transfers = context_transfers
        self.return_args = return_args

    def __str__(self):
        return (f"HALFunction(address=0x{self.address:x}, args={self.args}, " +
                f"context_transfers={self.context_transfers}, returnArgs={self.return_args})")

    def __repr__(self):
        return str(self)
