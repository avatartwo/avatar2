# What Is Avatar²?

Avatar is an orchestration framework designed to support dynamic analysis
of embedded devices. Avatar² is the second generation of the framework,
which has been completely re-designed and re-implemented from scratch to
improve performance, usability, and support for advanced features.

An Avatar² setup consists of three parts: 

 - A set of targets
 - A memory layout
 - An execution plan 

**Targets** are responsible for the execution and the analysis of the firmware
code. While it is possible to run Avatar² with a single target, most
configurations will have at least two (typically an emulator and a physical
device). The **memory layout** describes the different regions of memory and
their role in the system (e.g., the fact that may be mapped to an external
peripheral or connected to a file) as well as the _memory access rules_, i.e., how
memory read and write operations needs to be forwarded between targets.
Finally, the **execution plan** tells Avatar² how the actual execution of the
firmware needs to be divided among the targets in order to achieve the analyst goal.

If this sounds complex, it is because Avatar² is an extremely powerful and
flexible framework designed to adapt to different scenarios and support
complex configurations. However, a simple Avatar² example is quite
straightforward to write and understand. 


# Avatar² Architecture

The architecture of Avatar² consists of four different types of
components: the Avatar object itself, and a set of **targets**, **protocols**, and
**endpoints**. Avatar is the root-object that is responsible for orchestrating a
non-empty set of targets, which in turn communicate to their corresponding
endpoints using a number of protocols. Endpoints hereby can be anything - such as an
emulator, an analysis framework, or a physical device. Targets are instead
the python abstractions that are made available to Avatar to perform a
given analysis task. 

For clarity, the figure below gives a schematic overview over the avatar
architecture.

```
+------------------------------------------------------------------------------+
|                                   AVATAR                                     |
+----------------+--------------------------------------------+----------------+
                 |                                            |
                 |                                            |
          +------+------+                              +------+------+
          |  Target_1   |             ...              |  Target_n   |
          +------+------+                              +------+------+
                 |                                            |
     +-----------------------+                    +-----------------------+
     |           |           |                    |           |           |
+----+----+ +----+----+ +----+----+          +----+----+ +----+----+ +----+----+
|Execution| |  Memory | |Register |   ...    |Execution| |  Memory | |Register |
| Protocol| | Protocol| | Protocol|          | Protocol| | Protocol| | Protocol|
+----+----+ +----+----+ +-----+---+          +----+----+ +----+----+ +-----+---+
     |           |            |                   |           |            |
     |           |            |                   |           |            |
     |    +------+------+     |                   |    +------+------+     |
     +----+ Endpoint_1  +-----+       ...         +----+ Endpoint_n  +-----+
          +-------------+                              +-------------+
```

# "Hello World" from Avatar²

Every respectable documentation needs to start by showing how to say hello
to the world.

So here it is, an Avatar² script that modifies and executes a binary running
inside a gdb-server to print "Hello World!".

```python
import os
import subprocess

from avatar2 import *


filename = 'a.out'
GDB_PORT = 1234          

# This is a bare minimum elf-file, gracefully compiled from 
# https://github.com/abraithwaite/teensy
tiny_elf = (b'\x7f\x45\x4c\x46\x02\x01\x01\x00\xb3\x2a\x31\xc0\xff\xc0\xcd\x80'
            b'\x02\x00\x3e\x00\x01\x00\x00\x00\x08\x00\x40\x00\x00\x00\x00\x00'
            b'\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x00\x00\x00\x00\x40\x00\x38\x00\x01\x00\x00\x00\x00\x00\x00\x00'
            b'\x01\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00'
            b'\x78\x00\x00\x00\x00\x00\x00\x00\x78\x00\x00\x00\x00\x00\x00\x00'
            b'\x00\x00\x20\x00\x00\x00\x00\x00')
            
            

# Hello world shellcode
shellcode = (b'\x68\x72\x6c\x64\x21\x48\xb8\x48\x65\x6c\x6c\x6f\x20\x57\x6f\x50'
             b'\x48\x89\xef\x48\x89\xe6\x6a\x0c\x5a\x6a\x01\x58\x0f\x05')
          

# Save our executable to disk
with open(filename, 'wb') as f:
    f.write(tiny_elf)
os.chmod(filename, 0o744)

# Create the avatar instance and specify the architecture for this analysis
avatar = Avatar(arch=archs.x86.X86_64)

# Create the endpoint: a gdbserver connected to our tiny ELF file
gdbserver = subprocess.Popen('gdbserver --once 127.0.0.1:%d a.out' % GDB_PORT, shell=True)

# Create the corresponding target, using the GDBTarget backend
target = avatar.add_target("gdb", GDBTarget, gdb_port=GDB_PORT)

# Initialize the target. 
# This usually connects the target to the endpoint
target.init()

# Now it is possible to interact with the target.
# For example, we can insert our shellcode at the current point of execution
target.write_memory(target.read_register('pc'), len(shellcode),
                    shellcode, raw=True)

# We can now resume the execution in our target
# You should see hello world printed on your screen! :)
target.cont()

# Clean up!
os.remove(filename)
avatar.shutdown()
```
