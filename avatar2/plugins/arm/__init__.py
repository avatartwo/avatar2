class FuncArg:
    def __init__(self, value: int, needs_transfer=False, size=None):
        assert isinstance(value, int), "Address must be an integer"
        if needs_transfer:
            assert isinstance(size, int), "Size must be specified if needs_transfer is True"
        self.value: int = value
        self.needs_transfer: bool = needs_transfer
        self.size: int = size
