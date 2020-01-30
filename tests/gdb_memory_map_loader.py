import os
import subprocess

from avatar2 import *

filename = "a.out"
GDB_PORT = 1234

# This is a bare minimum elf-file, gracefully compiled from
# https://github.com/abraithwaite/teensy
tiny_elf = (
    b"\x7f\x45\x4c\x46\x02\x01\x01\x00\xb3\x2a\x31\xc0\xff\xc0\xcd\x80"
    b"\x02\x00\x3e\x00\x01\x00\x00\x00\x08\x00\x40\x00\x00\x00\x00\x00"
    b"\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x40\x00\x38\x00\x01\x00\x00\x00\x00\x00\x00\x00"
    b"\x01\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00"
    b"\x78\x00\x00\x00\x00\x00\x00\x00\x78\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x20\x00\x00\x00\x00\x00"
)


# Hello world shellcode
shellcode = (
    b"\x68\x72\x6c\x64\x21\x48\xb8\x48\x65\x6c\x6c\x6f\x20\x57\x6f\x50"
    b"\x48\x89\xef\x48\x89\xe6\x6a\x0c\x5a\x6a\x01\x58\x0f\x05"
)


# Save our executable to disk
with open(filename, "wb") as f:
    f.write(tiny_elf)
os.chmod(filename, 0o744)

# Create the avatar instance and specify the architecture for this analysis
avatar = Avatar(arch=archs.x86.X86_64)

# Load the gdb memory map loader
avatar.load_plugin("gdb_memory_map_loader")

# Create the endpoint: a gdbserver connected to our tiny ELF file
gdbserver = subprocess.Popen(
    "gdbserver --once 127.0.0.1:%d a.out" % GDB_PORT, shell=True
)

# Create the corresponding target, using the GDBTarget backend
target = avatar.add_target(GDBTarget, gdb_port=GDB_PORT)

# Initialize the target.
# This usually connects the target to the endpoint
target.init()

# Load the memory maps from the target.
target.load_memory_mappings()
assert len(avatar.memory_ranges)

# Now it is possible to interact with the target.
# For example, we can insert our shellcode at the current point of execution
target.write_memory(target.read_register("pc"), len(shellcode), shellcode, raw=True)

# We can now resume the execution in our target
# You should see hello world printed on your screen! :)
target.cont()

# Clean up!
os.remove(filename)
avatar.shutdown()
