from types import MethodType

from capstone import *


def forward_instructions(self, from_target, to_target,
                         memory_region, instructions=None,
                         read_from_file=True):
    if instructions == None:
        instructions = self.arch.unemulated_instructions

    if memory_region.forwarded == True:
        raise Exception("Cannot forward instructions from forwarded" +
                        " memory region")

    if read_from_file == True and memory_region.file == None:
        raise Exception("No file specified for this memory region")

    content = bytes()
    if read_from_file == True:
        with open(memory_region.file, 'rb') as f:
            content = f.read()
    else:
        content = from_target.rm(memory_region.address, memory_region.size)

    md = Cs(self.arch.capstone_arch, self.arch.capstone_mode)
    for (addr, size, op, _) in md.disasm_lite(content, memory_region.address):
        if op in instructions:
            self.log.debug("%s instruction found at %x. " +
                           "Adding transition.")
            self.add_transition(addr, from_target, to_target,
                                synch_regs=True)
            self.add_transition(addr + size, to_target, from_target,
                                synch_regs=True)


def load_plugin(avatar):
    if 'orchestrator' not in avatar.loaded_plugins:
        avatar.load_plugin('orchestrator')
    avatar.forward_instructions = MethodType(forward_instructions, avatar)
