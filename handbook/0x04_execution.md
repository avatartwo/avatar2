# Execution

After the set of targets and the memory layout have been defined, the actual 
analysis part of Avatar² can take place, which we denote as the _execution-phase_.

To tell Avatar² that the setup phase is completed and the actual execution can begin,
the targets have first to be initialized.

```python
from avatar2 import *

avatar = Avatar()

# Target setup
[...]

# Memory setup
[...]

# Initialize all targets and prepare for execution
avatar.init_targets()
```

During the execution phase, Avatar² can interact with each target 
to control its execution or to manipulate its memory or register values.


## Controlling the Target Execution

Avatar² can control the execution of a target by using a set of functionalities
very similar to those provided by a traditional debugger. In particular, all targets
support basic functionalities for
continuing, stepping, and stopping the execution. Additionally, breakpoints and
watchpoints can also be set as long as the underlying target supports these
features.

However, in comparison to traditional debuggers, Avatar² is not suspended while
a target is executing, as the analyst may want to setup complex
orchestration scheme involving parallel executions. Hence,
targets provide a _wait()_ method, which will force the avatar script to
wait until the target stops its execution.

Let's see how target execution can look like in an Avatar² script:

```python
# Get a target which we initialized before
qemu = avatar.targets['QemuTarget0']

# Set a breakpoint
bkpt = qemu.set_breakpoint(0x800e34)

# Continue execution
qemu.cont()

# Before doing anything else, wait for the breakpoint to be hit
qemu.wait()

# Remove the breakpoint
qemu.remove_breakpoint(bkpt)

# Step one instruction
qemu.step()
```

## Controlling the Target Registers

Avatar can  inspect and modify the register state of a target in a very easy manner:

```python

# Get the content of a register
r0 = qemu.read_register("r0")

# Set the content of a register
qemu.write_register("r0", 0x41414141)

# Shorter aliases to the exact same functions above
r0 = qemu.rr("r0")
qemu.wr("r0", 0x41414141)
```

## Controlling the Target Memory

Similar to the register state of a target, it is often desirable to obtain or
modify the memory content of a target, which is as simple as reading or writing
to a register:

```python
# read 4 bytes from addres 0x20000000
qemu.read_memory(0x20000000, 4)

# write 4 bytes to address 0x20000000
qemu.write_memory(0x20000000, 4, 0xdeadbeef)

# aliases
qemu.rm(0x20000000, 4)
qemu.wm(0x20000000, 4, 0xdeadbeef)
```

## Transferring the Execution State between Targets

One of the more interesting features of Avatar² is the possibility to transfer
the state between different targets during their execution, in order to allow
a successfull orchestration.
Take a look at the following example, which includes the target setup, the memory 
layout specification, and the transfer of execution (and state) 
from one target to another:

```python
from avatar2 import *

sample = 'firmware.bin'
openocd_conf = 'nucleo-l152re.cfg'

# Create avatar instance with custom output directory
avatar = Avatar(output_directory='/tmp/myavatar')

# Add first target
qemu = avatar.add_target(QemuTarget, 
                          gdb_executable="arm-none-eabi-gdb",
                          firmware=sample, cpu_model="cortex-m3",
                          executable="targets/qemu/arm-softmmu/qemu-system-")

# Add the second target
nucleo = avatar.add_target(OpenOCDTarget,
                           gdb_executable="arm-none-eabi-gdb", 
                           openocd_script=openocd_conf)

# Set up custom gdb ports to avoid collisions
qemu.gdb_port = 1234
nucleo.gdb_port = 1235

# Specify first memory range
rom  = avatar.add_memory_range(0x08000000, 0x1000000, 'rom', 
                                   file=sample)
# Specify second memory range
ram  = avatar.add_memory_range(0x20000000, 0x14000, 'ram')

# Initialize Targets
avatar.init_targets()

# Execute on the nucleo up to a specific address
nucleo.set_breakpoint(0x800B570)
nucleo.cont()
nucleo.wait()

# Transfer the state over to qemu
avatar.transfer_state(nucleo, qemu, synch_regs=True, synched_ranges=[ram])

# Continue execution on qemu
qemu.cont()
```
