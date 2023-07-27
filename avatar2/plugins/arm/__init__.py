class FuncArg:
    def __init__(self, value: int, needs_transfer=False, size=None):
        assert isinstance(value, int), "Address must be an integer"
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
